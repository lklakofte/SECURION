"""SECURION — bot de sécurité Discord piloté par commandes slash.

Pas de panneau web ni d'API distante. Les menus utilisent les composants natifs
de Discord et toutes les commandes sont des commandes d'application (/...).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict, deque, OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

VERSION = "4.3.0"
DATA_DIR = Path(os.getenv("SECURION_DATA_DIR", "data")).expanduser().resolve()
GUILDS_DIR = DATA_DIR / "guilds"
DB_PATH = DATA_DIR / "securion.sqlite3"
LEGACY_DB_PATH = DATA_DIR / "events.sqlite3"
if LEGACY_DB_PATH.exists():
    DB_PATH = LEGACY_DB_PATH
if os.name != "nt":
    os.umask(0o077)
DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
GUILDS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def restrict_file_permissions(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except (OSError, NotImplementedError):
        logging.getLogger("securion").warning("Permissions privées non configurables sur %s", path.name)


restrict_file_permissions(DATA_DIR, 0o700)
restrict_file_permissions(GUILDS_DIR, 0o700)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("securion")

MODULE_LABELS = {
    "anti_spam": "Anti-spam",
    "anti_mentions": "Anti-mentions",
    "anti_invites": "Liens d'invitation",
    "anti_raid": "Anti-raid",
    "anti_webhooks": "Surveillance des webhooks",
    "anti_channels": "Surveillance des salons",
    "anti_roles": "Surveillance des rôles",
    "anti_bots": "Surveillance des bots ajoutés",
}

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "safe_mode": False,
    "global_level": 5,
    "auto_timeout": False,
    "auto_warning": True,
    "delete_triggering_message": True,
    "warning_limit": 5,
    "warning_window_days": 30,
    "temporary_ban_days": [2, 7, 30],
    "modules": {key: True for key in MODULE_LABELS},
    "thresholds": {
        "spam_count": 5, "spam_seconds": 5, "mention_count": 5,
        "raid_joins": 7, "raid_seconds": 20,
        "destructive_actions": 3, "destructive_seconds": 60,
    },
    "whitelist_users": [],
    "whitelist_roles": [],
    "access_users": [],
    "access_roles": [],
    "access_control_enabled": True,
    "log_channel_id": 0,
}

INVITE_RE = re.compile(r"(?:discord\.gg/|discord(?:app)?\.com/invite/)[A-Za-z0-9-]+", re.I)
message_windows: OrderedDict[tuple[int, int], deque[tuple[float, str]]] = OrderedDict()
join_windows: dict[int, deque[float]] = defaultdict(deque)
audit_windows: dict[tuple[int, int, str], deque[float]] = defaultdict(deque)
raid_alert_at: dict[int, float] = defaultdict(float)
audit_alert_at: dict[tuple[int, int, str], float] = defaultdict(float)
auto_warning_at: dict[tuple[int, int], float] = defaultdict(float)
expiry_notice_at: dict[int, float] = defaultdict(float)
warning_locks: dict[tuple[int, int], asyncio.Lock] = {}


def _deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _clean_ids(values: Any) -> list[int]:
    if not isinstance(values, list):
        return []
    result: list[int] = []
    for value in values[:500]:
        try:
            item = int(value)
        except (TypeError, ValueError):
            continue
        if 0 < item < 2**64 and item not in result:
            result.append(item)
    return result


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        number = default
    return max(low, min(high, number))


def _guild_config_path(guild_id: int) -> Path:
    return GUILDS_DIR / f"{int(guild_id)}.json"


def get_config(guild_id: int) -> dict[str, Any]:
    try:
        raw = json.loads(_guild_config_path(guild_id).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except (OSError, ValueError, TypeError):
        raw = {}
    cfg = _deep_merge(DEFAULT_CONFIG, raw)
    if not isinstance(cfg.get("modules"), dict):
        cfg["modules"] = dict(DEFAULT_CONFIG["modules"])
    if not isinstance(cfg.get("thresholds"), dict):
        cfg["thresholds"] = dict(DEFAULT_CONFIG["thresholds"])
    cfg["global_level"] = _bounded_int(cfg.get("global_level"), 5, 1, 10)
    cfg["log_channel_id"] = _bounded_int(cfg.get("log_channel_id"), 0, 0, 2**64 - 1)
    for key in MODULE_LABELS:
        value = cfg["modules"].get(key, True)
        cfg["modules"][key] = value if isinstance(value, bool) else DEFAULT_CONFIG["modules"][key]
    for key, low, high in (
        ("spam_count", 2, 100), ("spam_seconds", 1, 120),
        ("mention_count", 2, 50), ("raid_joins", 2, 200),
        ("raid_seconds", 5, 300), ("destructive_actions", 2, 20),
        ("destructive_seconds", 10, 300),
    ):
        cfg["thresholds"][key] = _bounded_int(
            cfg["thresholds"].get(key), DEFAULT_CONFIG["thresholds"][key], low, high
        )
    # Ce seuil n'est pas réglable dans le panel : garder une règle identique
    # pour chaque serveur évite qu'une ancienne configuration rende le test trompeur.
    cfg["thresholds"]["spam_count"] = 5
    cfg["thresholds"]["spam_seconds"] = 5
    cfg["whitelist_users"] = _clean_ids(cfg.get("whitelist_users", []))
    cfg["whitelist_roles"] = _clean_ids(cfg.get("whitelist_roles", []))
    cfg["access_users"] = _clean_ids(cfg.get("access_users", []))
    cfg["access_roles"] = _clean_ids(cfg.get("access_roles", []))
    cfg["access_control_enabled"] = bool(cfg.get("access_control_enabled", True))
    # Le seuil demandé pour SECURION est fixe : cinq avertissements.
    # Une ancienne configuration ne doit pas modifier cette règle.
    cfg["warning_limit"] = 5
    cfg["warning_window_days"] = _bounded_int(cfg.get("warning_window_days"), 30, 1, 365)
    raw_durations = cfg.get("temporary_ban_days", [2, 7, 30])
    if not isinstance(raw_durations, list) or len(raw_durations) != 3:
        raw_durations = [2, 7, 30]
    cfg["temporary_ban_days"] = [_bounded_int(value, default, 1, 3650)
                                 for value, default in zip(raw_durations, (2, 7, 30))]
    for key, default in (("enabled", True), ("safe_mode", False),
                         ("auto_timeout", False), ("auto_warning", True),
                         ("delete_triggering_message", True)):
        cfg[key] = bool(cfg.get(key, default))
    return cfg


def save_config(guild_id: int, cfg: dict[str, Any]) -> None:
    path = _guild_config_path(guild_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    restrict_file_permissions(temporary, 0o600)
    temporary.replace(path)
    restrict_file_permissions(path, 0o600)


def init_db() -> None:
    with sqlite3.connect(DB_PATH, timeout=15) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
                guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL DEFAULT 0,
                username TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
                severity INTEGER NOT NULL DEFAULT 1, detail TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT ''
            )"""
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_guild ON events(guild_id, id DESC)")
        con.execute(
            """CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
                username TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
                removed INTEGER NOT NULL DEFAULT 0
            )"""
        )
        warning_columns = {row[1] for row in con.execute("PRAGMA table_info(warnings)")}
        if "removed" not in warning_columns:
            con.execute("ALTER TABLE warnings ADD COLUMN removed INTEGER NOT NULL DEFAULT 0")
        con.execute("CREATE INDEX IF NOT EXISTS idx_warnings_user ON warnings(guild_id,user_id,id DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_warnings_active ON warnings(guild_id,user_id,consumed,removed,expires_at)")
        con.execute(
            """CREATE TABLE IF NOT EXISTS sanctions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
                username TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
                reason TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL, expires_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                source_legacy_id INTEGER
            )"""
        )
        sanction_columns = {row[1] for row in con.execute("PRAGMA table_info(sanctions)")}
        if "source_legacy_id" not in sanction_columns:
            con.execute("ALTER TABLE sanctions ADD COLUMN source_legacy_id INTEGER")
        con.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sanctions_legacy_id "
            "ON sanctions(source_legacy_id)"
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_sanctions_expiry ON sanctions(kind,status,expires_at)")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "moderation_bans" in tables:
            con.execute(
                """INSERT OR IGNORE INTO sanctions
                   (guild_id,user_id,username,kind,reason,actor,created_at,expires_at,status,source_legacy_id)
                   SELECT guild_id,user_id,username,
                          CASE WHEN kind IN ('automatic','temporary') THEN 'temporary' ELSE 'manual' END,
                          reason,actor,created_at,expires_at,status,id
                   FROM moderation_bans"""
            )
    restrict_file_permissions(DB_PATH, 0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = DB_PATH.with_name(DB_PATH.name + suffix)
        if sidecar.exists():
            restrict_file_permissions(sidecar, 0o600)


def record_event(guild_id: int, user_id: int, username: str, kind: str,
                 severity: int, detail: str, action: str) -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            con.execute(
                "INSERT INTO events(at,guild_id,user_id,username,kind,severity,detail,action) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (utc_now_iso(), int(guild_id), int(user_id or 0), str(username)[:100], str(kind)[:100],
                 max(1, min(10, int(severity))), str(detail)[:900], str(action)[:250]),
            )
    except (sqlite3.Error, TypeError, ValueError):
        log.exception("Impossible d'enregistrer un événement")


def is_exempt(member: discord.Member, cfg: dict[str, Any]) -> bool:
    if member.bot or member.id in cfg["whitelist_users"] or member.id in cfg["access_users"]:
        return True
    if any(role.id in cfg["whitelist_roles"] or role.id in cfg["access_roles"] for role in member.roles):
        return True
    perms = member.guild_permissions
    return bool(perms.administrator or perms.manage_guild or perms.manage_messages or perms.moderate_members)


async def send_log(guild: discord.Guild, content: str) -> bool:
    channel_id = int(get_config(guild.id).get("log_channel_id") or 0)
    if not channel_id:
        return False
    channel = guild.get_channel(channel_id)
    if channel is None:
        try:
            channel = await bot.fetch_channel(channel_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return False
    if not isinstance(channel, (discord.TextChannel, discord.Thread)):
        return False
    if getattr(getattr(channel, "guild", None), "id", None) != guild.id:
        return False
    me = guild.me
    if me is None:
        return False
    try:
        perms = channel.permissions_for(me)
        can_send = perms.send_messages_in_threads if isinstance(channel, discord.Thread) else perms.send_messages
        if not perms.view_channel or not can_send:
            return False
        await channel.send(content[:1900], allowed_mentions=discord.AllowedMentions.none())
        return True
    except (discord.Forbidden, discord.NotFound, discord.HTTPException):
        log.warning("Envoi impossible dans le salon de logs %s (%s)", channel_id, guild.id)
        return False


async def send_private(interaction: discord.Interaction, content: str) -> None:
    if interaction.response.is_done():
        await interaction.followup.send(content, ephemeral=True)
    else:
        await interaction.response.send_message(content, ephemeral=True)


def staff_has(interaction: discord.Interaction, permission: str | None = None) -> bool:
    if not isinstance(interaction.user, discord.Member) or interaction.guild is None:
        return False
    perms = interaction.user.guild_permissions
    if permission is None:
        return bool(perms.administrator or perms.manage_guild)
    return bool(perms.administrator or getattr(perms, permission, False))


def has_command_access(interaction: discord.Interaction, permission: str | None = None) -> bool:
    if not isinstance(interaction.user, discord.Member) or interaction.guild is None:
        return False
    member = interaction.user
    perms = member.guild_permissions
    if perms.administrator or perms.manage_guild:
        return True
    cfg = get_config(interaction.guild.id)
    is_listed = member.id in cfg["access_users"] or any(role.id in cfg["access_roles"] for role in member.roles)
    if cfg["access_control_enabled"]:
        return is_listed
    if is_listed:
        return True
    return bool(permission and getattr(perms, permission, False))


async def reject_permission(
    interaction: discord.Interaction,
    permission: str | None = None,
    *,
    admin_only: bool | None = None,
) -> bool:
    if interaction.guild is None:
        await send_private(interaction, "Cette commande doit être utilisée dans un serveur.")
        return True
    if admin_only is None:
        admin_only = permission is None
    allowed = staff_has(interaction) if admin_only else has_command_access(interaction, permission)
    if not allowed:
        names = {
            None: "administrateurs ou personnes/rôles autorisés dans /panel",
            "moderate_members": "modérateurs ou personnes/rôles autorisés dans /panel",
            "kick_members": "personnes autorisées à expulser ou autorisées dans /panel",
            "ban_members": "personnes autorisées à bannir ou autorisées dans /panel",
        }
        await send_private(interaction, f"Commande réservée aux {names.get(permission, 'membres autorisés')}.")
        return True
    return False


async def can_bot_moderate(guild: discord.Guild, member: discord.Member) -> tuple[bool, str]:
    me = guild.me
    if member.id == guild.owner_id:
        return False, "Le propriétaire du serveur ne peut pas être sanctionné."
    if me is None or member.top_role >= me.top_role:
        return False, "Place le rôle de SECURION au-dessus de celui du membre."
    return True, ""


async def dm_member(member: discord.Member, content: str) -> bool:
    try:
        await member.send(content, allowed_mentions=discord.AllowedMentions.none())
        return True
    except (discord.Forbidden, discord.HTTPException):
        return False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def issue_warning(
    member: discord.Member,
    reason: str,
    actor: str,
    *,
    allow_escalation: bool = True,
) -> dict[str, Any]:
    key = (member.guild.id, member.id)
    lock = warning_locks.setdefault(key, asyncio.Lock())
    async with lock:
        return await _issue_warning_locked(
            member, reason, actor, allow_escalation=allow_escalation
        )


async def _issue_warning_locked(
    member: discord.Member,
    reason: str,
    actor: str,
    *,
    allow_escalation: bool,
) -> dict[str, Any]:
    """Enregistre un avertissement et applique l'escalade après cinq avertissements actifs."""
    guild = member.guild
    cfg = get_config(guild.id)
    reason = reason.strip()[:500] or "Aucun motif indiqué"
    now = datetime.now(timezone.utc)
    created_at = now.isoformat(timespec="seconds")
    expires_at = (now + timedelta(days=cfg["warning_window_days"])).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        cursor = con.execute(
            "INSERT INTO warnings(guild_id,user_id,username,reason,actor,created_at,expires_at,consumed) "
            "VALUES(?,?,?,?,?,?,?,0)",
            (guild.id, member.id, str(member)[:100], reason, actor[:100], created_at, expires_at),
        )
        warning_id = int(cursor.lastrowid)
        rows = con.execute(
            "SELECT id FROM warnings WHERE guild_id=? AND user_id=? AND consumed=0 AND removed=0 AND expires_at>? "
            "ORDER BY id ASC",
            (guild.id, member.id, created_at),
        ).fetchall()
    warning_ids = [int(row[0]) for row in rows]
    count = len(warning_ids)
    dm_sent = await dm_member(
        member,
        f"Tu as reçu un avertissement sur {guild.name}.\nMotif : {reason}\n"
        f"Avertissements actifs : {count}/{cfg['warning_limit']} (fenêtre de {cfg['warning_window_days']} jours).",
    )
    record_event(guild.id, member.id, str(member), "avertissement", 3, reason,
                 f"par {actor} · avertissements actifs {count}/{cfg['warning_limit']}")
    result: dict[str, Any] = {
        "id": warning_id, "count": count, "limit": cfg["warning_limit"],
        "dm_sent": dm_sent, "sanction": None,
    }

    if count >= cfg["warning_limit"] and allow_escalation:
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            previous_temporary = int(con.execute(
                "SELECT COUNT(*) FROM sanctions WHERE guild_id=? AND user_id=? AND kind='temporary'",
                (guild.id, member.id),
            ).fetchone()[0])
        if previous_temporary >= 3:
            kind = "permanent"
            duration_days = None
            ban_reason = "Nouvelle série de 5 avertissements après 3 bannissements temporaires"
            label = "bannissement définitif après 3 bannissements temporaires"
        else:
            kind = "temporary"
            duration_days = cfg["temporary_ban_days"][previous_temporary]
            ban_reason = f"{cfg['warning_limit']} avertissements actifs · bannissement temporaire n°{previous_temporary + 1}"
            label = f"bannissement temporaire de {duration_days} jours (n°{previous_temporary + 1}/3)"

        allowed, hierarchy_message = await can_bot_moderate(guild, member)
        me = guild.me
        if not allowed:
            sanction_result = {"success": False, "message": hierarchy_message, "label": label}
        elif me is None or not me.guild_permissions.ban_members:
            sanction_result = {"success": False, "message": "Permission Bannir des membres manquante pour SECURION.", "label": label}
        else:
            duration_text = (
                f"temporaire de {duration_days} jours" if duration_days is not None else "définitif"
            )
            dm_sent = await dm_member(
                member,
                f"SECURION va t'appliquer un bannissement {duration_text} sur {guild.name}.\n"
                f"Motif : {ban_reason}\nSi tu penses qu'il s'agit d'une erreur, contacte l'équipe du serveur.",
            )
            try:
                await guild.ban(member, reason=f"SECURION · {ban_reason}"[:500], delete_message_seconds=0)
                created = utc_now_iso()
                expiry = (
                    (datetime.now(timezone.utc) + timedelta(days=duration_days)).isoformat(timespec="seconds")
                    if duration_days is not None else None
                )
                with sqlite3.connect(DB_PATH, timeout=10) as con:
                    con.execute(
                        "INSERT INTO sanctions(guild_id,user_id,username,kind,reason,actor,created_at,expires_at,status) "
                        "VALUES(?,?,?,?,?,?,?,?, 'active')",
                        (guild.id, member.id, str(member)[:100], kind, ban_reason, actor[:100], created, expiry),
                    )
                    con.executemany(
                        "UPDATE warnings SET consumed=1 WHERE id=?",
                        [(warning_id,) for warning_id in warning_ids],
                    )
                record_event(guild.id, member.id, str(member), "bannissement automatique", 10,
                             ban_reason, label)
                await send_log(
                    guild,
                    f"⛔ **Escalade automatique** · {member} ({member.id})\n"
                    f"{count} avertissements actifs · {label}\nMotif : {ban_reason}\n"
                    f"Message privé : {'envoyé' if dm_sent else 'impossible (MP fermés ou indisponibles)'}",
                )
                sanction_result = {"success": True, "message": label, "label": label}
            except discord.Forbidden:
                if dm_sent:
                    await dm_member(member, "Le bannissement annoncé par SECURION n'a finalement pas pu être appliqué. Contacte l'équipe du serveur si besoin.")
                sanction_result = {"success": False, "message": "Discord a refusé le ban : vérifie la permission et la hiérarchie.", "label": label}
            except discord.HTTPException as exc:
                if dm_sent:
                    await dm_member(member, "Le bannissement annoncé par SECURION n'a finalement pas pu être appliqué. Contacte l'équipe du serveur si besoin.")
                sanction_result = {"success": False, "message": f"Discord a refusé le ban (HTTP {exc.status}).", "label": label}
        result["sanction"] = sanction_result

    suffix = f" · escalade : {result['sanction']['message']}" if result["sanction"] else ""
    await send_log(
        guild,
        f"⚠️ **Avertissement {count}/{cfg['warning_limit']}** · {member} ({member.id})\n"
        f"Motif : {reason}\nPar : {actor}{suffix}",
    )
    return result


def make_embed(title: str, description: str, color: int = 0xE53945) -> discord.Embed:
    return discord.Embed(title=title, description=description, color=color)


class SecurionBot(commands.Bot):
    async def setup_hook(self) -> None:
        init_db()
        test_guild_id = os.getenv("SECURION_TEST_GUILD_ID", "").strip()
        if test_guild_id.isdigit():
            guild = discord.Object(id=int(test_guild_id))
            self.tree.copy_global_to(guild=guild)
            synced = await self.tree.sync(guild=guild)
            log.info("Commandes de test synchronisées : %s", len(synced))
        else:
            synced = await self.tree.sync()
            log.info("Commandes globales synchronisées : %s", len(synced))

    async def on_ready(self) -> None:
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name="la sécurité de vos serveurs")
        )
        if not temporary_ban_expiry.is_running():
            temporary_ban_expiry.start()
        log.info("Connecté comme %s sur %s serveur(s)", self.user, len(self.guilds))
        print(f"SECURION {VERSION} connecté : {self.user} | {len(self.guilds)} serveur(s)", flush=True)


intents = discord.Intents.default()
intents.guilds = True
intents.guild_messages = True
intents.members = True
intents.message_content = True
intents.moderation = True
bot = SecurionBot(command_prefix=commands.when_mentioned, intents=intents)


@tasks.loop(minutes=1)
async def temporary_ban_expiry() -> None:
    now = utc_now_iso()
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            rows = con.execute(
                "SELECT id,guild_id,user_id,username FROM sanctions "
                "WHERE kind='temporary' AND status='active' AND expires_at IS NOT NULL AND expires_at<=? LIMIT 100",
                (now,),
            ).fetchall()
    except sqlite3.Error:
        # Une erreur SQLite ponctuelle ne doit pas arrêter définitivement la tâche.
        log.exception("Impossible de charger les bans temporaires arrivés à échéance")
        return
    for sanction_id, guild_id, user_id, username in rows:
        guild = bot.get_guild(int(guild_id))
        if guild is None:
            continue
        try:
            await guild.unban(discord.Object(id=int(user_id)), reason="SECURION · fin du bannissement temporaire")
        except discord.NotFound:
            pass
        except discord.Forbidden:
            if time.monotonic() - expiry_notice_at[int(sanction_id)] >= 300:
                expiry_notice_at[int(sanction_id)] = time.monotonic()
                await send_log(
                    guild,
                    f"⚠️ SECURION n'a pas pu lever le ban temporaire de {username} ({user_id}). "
                    "Vérifie sa permission Bannir des membres.",
                )
            continue
        except discord.HTTPException:
            log.exception("Échec du débannissement automatique pour %s sur %s", user_id, guild_id)
            continue
        try:
            with sqlite3.connect(DB_PATH, timeout=10) as con:
                con.execute("UPDATE sanctions SET status='expired' WHERE id=? AND status='active'", (sanction_id,))
        except sqlite3.Error:
            # Au prochain cycle, Discord répondra NotFound et l'historique sera réessayé.
            log.exception("Impossible de mettre à jour l'historique du ban temporaire %s", sanction_id)
            continue
        record_event(int(guild_id), int(user_id), str(username), "fin de bannissement temporaire", 2,
                     "La durée du bannissement temporaire est terminée.", "débannissement automatique")
        await send_log(guild, f"✅ Ban temporaire terminé · {username} ({user_id}) peut rejoindre à nouveau.")


@temporary_ban_expiry.before_loop
async def before_temporary_ban_expiry() -> None:
    await bot.wait_until_ready()


HELP_PAGES = {
    "accueil": ("🏠 Bienvenue sur SECURION",
        "Bot de sécurité pour ton serveur. Toutes les commandes commencent par /.\n"
        "Utilise /help pour ce guide et /statut pour voir les protections actives.\n"
        "Les réponses de gestion sont privées et visibles uniquement par toi."),
    "moderation": ("🔨 Modération",
        "/sanction avertir — enregistrer un avertissement.\n"
        "/sanction timeout — appliquer un timeout.\n"
        "/sanction expulser — expulser un membre.\n"
        "/sanction bannir — bannir un membre.\n"
        "/sanction debannir — lever un ban avec son identifiant Discord.\n"
        "Les rôles et personnes autorisés dans /panel > Accès peuvent avertir et bannir.\n"
        "/historique membre — consulter les événements récents d'un membre.\n"
        "/historique avertissements — voir les avertissements, leurs motifs et leur auteur.\n"
        "/historique actions — retirer un avertissement, réinitialiser le compteur, retirer un timeout ou débannir."),
    "protection": ("🛡️ Protections",
        "Détection du spam, des mentions massives, des liens d'invitation et des arrivées groupées. "
        "Surveillance des changements sensibles et des actions destructrices.\n"
        "Les alertes anti-raid et anti-nuke ne déclenchent pas de sanctions automatiques."),
    "configuration": ("⚙️ Configuration",
        "/panel — ouvrir la configuration et les accès dans Discord.\n"
        "/protection pause ou /protection reprendre — contrôler les protections.\n"
        "/protection module — activer ou désactiver un module.\n"
        "/protection prudent — activer ou désactiver le mode prudent.\n"
        "/diagnostic — vérifier l'anti-spam et les permissions des salons.\n"
        "/protection timeout_auto — activer ou couper le timeout automatique.\n"
        "/protection niveau — régler la sensibilité de 1 à 10.\n"
        "/wl ajouter, /wl retirer, /wl liste — gérer la liste blanche.\n"
        "/historique avertissements — voir qui a été averti.\n"
        "/historique actions — gérer les avertissements, timeouts et bannissements."),
}


class HelpCategorySelect(discord.ui.Select):
    def __init__(self, view: "HelpView"):
        self.help_view = view
        options = [
            discord.SelectOption(label="Accueil", value="accueil", emoji="🏠"),
            discord.SelectOption(label="Modération", value="moderation", emoji="🔨"),
            discord.SelectOption(label="Protections", value="protection", emoji="🛡️"),
            discord.SelectOption(label="Configuration", value="configuration", emoji="⚙️"),
        ]
        super().__init__(placeholder="Choisir une catégorie", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.help_view.page = self.values[0]
        title, description = HELP_PAGES[self.help_view.page]
        embed = make_embed(title, description, 0x5865F2)
        embed.set_footer(text=f"SECURION {VERSION} · commandes slash")
        await interaction.response.edit_message(embed=embed, view=self.help_view)


class HelpView(discord.ui.View):
    def __init__(self, owner_id: int):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.page = "accueil"
        self.add_item(HelpCategorySelect(self))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Lance /help pour ouvrir ton propre menu.", ephemeral=True)
            return False
        return True


@bot.tree.command(name="help", description="Voir les commandes et protections de SECURION")
async def help_command(interaction: discord.Interaction) -> None:
    if interaction.guild is not None:
        cfg = get_config(interaction.guild.id)
        if cfg["access_control_enabled"] and not has_command_access(interaction):
            return await send_private(interaction, "Tu n'as pas de rôle ou d'accès autorisé dans /panel.")
    title, description = HELP_PAGES["accueil"]
    embed = make_embed(title, description, 0x5865F2)
    embed.set_footer(text=f"SECURION {VERSION} · sélectionne une catégorie")
    await interaction.response.send_message(embed=embed, view=HelpView(interaction.user.id), ephemeral=True)


CONFIG_CATEGORIES = [
    ("Accueil", "accueil", "🏠"), ("Protections", "protections", "🛡️"),
    ("Salon de logs", "journaux", "📋"), ("Avertissements", "warnings", "⚠️"),
    ("Accès", "access", "🔐"),
]


class ConfigCategorySelect(discord.ui.Select):
    def __init__(self, view: "ConfigView"):
        self.config_view = view
        super().__init__(
            placeholder="Choisir une catégorie",
            options=[discord.SelectOption(label=label, value=value, emoji=emoji, default=value == view.category)
                     for label, value, emoji in CONFIG_CATEGORIES],
            min_values=1, max_values=1, row=0,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        self.config_view.category = self.values[0]
        self.config_view.render()
        await interaction.response.edit_message(embed=self.config_view.make_embed(), view=self.config_view)


class ModuleSelect(discord.ui.Select):
    def __init__(self, view: "ConfigView"):
        self.config_view = view
        cfg = get_config(view.guild_id)
        options = [
            discord.SelectOption(label=label, value=key, default=key == view.selected_module,
                                 description="Activé" if cfg["modules"].get(key) else "Désactivé")
            for key, label in MODULE_LABELS.items()
        ]
        super().__init__(placeholder="Choisir un module", options=options, min_values=1, max_values=1, row=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.config_view.selected_module = self.values[0]
        self.config_view.render()
        await interaction.response.edit_message(embed=self.config_view.make_embed(), view=self.config_view)


class AccessRoleSelect(discord.ui.RoleSelect):
    def __init__(self, view: "ConfigView"):
        self.config_view = view
        super().__init__(placeholder="Choisir un rôle à autoriser", min_values=1, max_values=1, row=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.config_view.selected_role_id = self.values[0].id
        self.config_view.render()
        await interaction.response.edit_message(embed=self.config_view.make_embed(), view=self.config_view)


class AccessUserSelect(discord.ui.UserSelect):
    def __init__(self, view: "ConfigView"):
        self.config_view = view
        super().__init__(placeholder="Choisir une personne à autoriser", min_values=1, max_values=1, row=3)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.config_view.selected_user_id = self.values[0].id
        self.config_view.render()
        await interaction.response.edit_message(embed=self.config_view.make_embed(), view=self.config_view)


class ChannelIdModal(discord.ui.Modal, title="Définir le salon de logs"):
    channel_id = discord.ui.TextInput(
        label="Identifiant du salon",
        placeholder="Colle l'ID du salon ou sa mention #salon",
        required=True,
        max_length=30,
    )

    def __init__(self, guild_id: int, owner_id: int):
        super().__init__(timeout=180)
        self.guild_id = guild_id
        self.owner_id = owner_id

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None or interaction.guild.id != self.guild_id or interaction.user.id != self.owner_id:
            return await send_private(interaction, "Cette fenêtre de configuration n'est plus valide.")
        if not staff_has(interaction):
            return await send_private(interaction, "Seuls les administrateurs et responsables peuvent modifier le salon.")
        match = re.fullmatch(r"(?:<#)?(\d{15,22})>?", str(self.channel_id.value).strip())
        if not match:
            return await send_private(interaction, "Identifiant invalide. Colle l'ID numérique ou la mention du salon.")
        channel_id = int(match.group(1))
        channel = interaction.guild.get_channel(channel_id)
        if channel is None:
            try:
                channel = await bot.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                return await send_private(interaction, "Salon introuvable ou inaccessible.")
        if getattr(getattr(channel, "guild", None), "id", None) != self.guild_id:
            return await send_private(interaction, "Ce salon ne se trouve pas dans ce serveur.")
        if not isinstance(channel, (discord.TextChannel, discord.Thread)):
            return await send_private(interaction, "Choisis un salon textuel ou un fil de discussion.")
        me = interaction.guild.me
        if me is None:
            return await send_private(interaction, "SECURION n'est pas prêt à vérifier ce salon.")
        permissions = channel.permissions_for(me)
        can_send = permissions.send_messages_in_threads if isinstance(channel, discord.Thread) else permissions.send_messages
        if not permissions.view_channel or not can_send:
            return await send_private(interaction, "SECURION doit pouvoir voir ce salon et y envoyer des messages.")
        cfg = get_config(self.guild_id)
        cfg["log_channel_id"] = channel_id
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 1,
                     f"Salon de logs défini sur {channel_id}", "par un administrateur")
        await send_private(interaction, f"Salon de logs enregistré : {channel.mention}")


class ConfigView(discord.ui.View):
    def __init__(self, guild_id: int, owner_id: int):
        super().__init__(timeout=240)
        self.guild_id = guild_id
        self.owner_id = owner_id
        self.category = "accueil"
        self.selected_module = "anti_spam"
        self.selected_role_id: int | None = None
        self.selected_user_id: int | None = None
        self.render()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Lance /panel pour ouvrir ton propre menu.", ephemeral=True)
            return False
        if not staff_has(interaction):
            await interaction.response.send_message("Seuls les administrateurs et responsables peuvent modifier la configuration.", ephemeral=True)
            return False
        return True

    def _button(self, label: str, style: discord.ButtonStyle, callback, row: int) -> discord.ui.Button:
        button = discord.ui.Button(label=label, style=style, row=row)
        button.callback = callback
        return button

    def render(self) -> "ConfigView":
        self.clear_items()
        self.add_item(ConfigCategorySelect(self))
        cfg = get_config(self.guild_id)
        if self.category == "accueil":
            label = "Mettre en pause" if cfg["enabled"] else "Reprendre"
            style = discord.ButtonStyle.danger if cfg["enabled"] else discord.ButtonStyle.success
            self.add_item(self._button(label, style, self.toggle_enabled, 1))
            label = "Mode prudent : ON" if cfg["safe_mode"] else "Mode prudent : OFF"
            self.add_item(self._button(label, discord.ButtonStyle.primary, self.toggle_safe_mode, 1))
            label = "Timeout automatique : ON" if cfg["auto_timeout"] else "Timeout automatique : OFF"
            style = discord.ButtonStyle.danger if cfg["auto_timeout"] else discord.ButtonStyle.secondary
            self.add_item(self._button(label, style, self.toggle_auto_timeout, 2))
            self.add_item(self._button("Réactiver l'anti-spam auto", discord.ButtonStyle.success,
                                       self.activate_auto_protection, 3))
        elif self.category == "protections":
            self.add_item(ModuleSelect(self))
            self.add_item(self._button("Activer / désactiver", discord.ButtonStyle.primary, self.toggle_module, 2))
        elif self.category == "journaux":
            self.add_item(self._button("Saisir l'ID du salon", discord.ButtonStyle.primary, self.set_log_channel, 1))
            self.add_item(self._button("Retirer le salon de logs", discord.ButtonStyle.secondary, self.clear_log_channel, 2))
        elif self.category == "warnings":
            label = "Avertissements automatiques : ON" if cfg["auto_warning"] else "Avertissements automatiques : OFF"
            style = discord.ButtonStyle.success if cfg["auto_warning"] else discord.ButtonStyle.secondary
            self.add_item(self._button(label, style, self.toggle_auto_warning, 1))
        elif self.category == "access":
            self.add_item(AccessRoleSelect(self))
            self.add_item(self._button("Autoriser ce rôle", discord.ButtonStyle.success, self.add_access_role, 2))
            self.add_item(self._button("Retirer ce rôle", discord.ButtonStyle.secondary, self.remove_access_role, 2))
            strict_label = "Accès strict : ON" if cfg["access_control_enabled"] else "Accès strict : OFF"
            strict_style = discord.ButtonStyle.danger if cfg["access_control_enabled"] else discord.ButtonStyle.secondary
            self.add_item(self._button(strict_label, strict_style, self.toggle_access_strict, 2))
            self.add_item(AccessUserSelect(self))
            self.add_item(self._button("Autoriser cette personne", discord.ButtonStyle.success, self.add_access_user, 4))
            self.add_item(self._button("Retirer cette personne", discord.ButtonStyle.secondary, self.remove_access_user, 4))
        return self

    def make_embed(self, notice: str = "") -> discord.Embed:
        cfg = get_config(self.guild_id)
        prefix = f"{notice}\n\n" if notice else ""
        if self.category == "accueil":
            active = sum(cfg["modules"].values())
            body = (f"{prefix}**État :** {'Actif' if cfg['enabled'] else 'En pause'}\n"
                    f"**Mode prudent :** {'Activé' if cfg['safe_mode'] else 'Désactivé'}\n"
                    f"**Avertissements automatiques :** {'Activés' if cfg['auto_warning'] else 'Désactivés'}\n"
                    f"**Timeout automatique :** {'Activé' if cfg['auto_timeout'] else 'Désactivé'}\n"
                    f"**Niveau :** {cfg['global_level']}/10\n"
                    f"**Modules actifs :** {active}/{len(MODULE_LABELS)}\n\n"
                    f"À {cfg['warning_limit']} avertissements en {cfg['warning_window_days']} jours : "
                    f"bans temporaires de {', '.join(str(days) + ' j' for days in cfg['temporary_ban_days'])}. "
                    "Après ces trois bans, la prochaine série de 5 avertissements entraîne le ban définitif.")
            title = "⚙️ Configuration de SECURION"
        elif self.category == "protections":
            lines = [f"{'🟢' if cfg['modules'].get(key) else '⚪'} **{label}**"
                     for key, label in MODULE_LABELS.items()]
            selected = "activé" if cfg["modules"].get(self.selected_module) else "désactivé"
            body = f"{prefix}{chr(10).join(lines)}\n\nModule sélectionné : **{MODULE_LABELS[self.selected_module]}** ({selected})."
            title = "🛡️ Protections"
        elif self.category == "journaux":
            channel_id = cfg["log_channel_id"]
            channel = f"<#{channel_id}>" if channel_id else "Aucun salon configuré"
            body = f"{prefix}Les alertes, avertissements et sanctions seront envoyés ici : {channel}.\nUtilise le bouton pour coller l'ID numérique du salon."
            title = "📋 Journaux de sécurité"
        elif self.category == "warnings":
            with sqlite3.connect(DB_PATH, timeout=10) as con:
                rows = con.execute(
                    """SELECT w.created_at,w.user_id,w.username,w.reason,w.actor,w.consumed,w.expires_at,
                              (SELECT COUNT(*) FROM warnings active
                               WHERE active.guild_id=w.guild_id AND active.user_id=w.user_id
                               AND active.consumed=0 AND active.removed=0 AND active.expires_at>?) AS active_count
                       FROM warnings w WHERE w.guild_id=? ORDER BY w.id DESC LIMIT 8""",
                    (utc_now_iso(), self.guild_id),
                ).fetchall()
            recent = "\n".join(
                f"• {at} · <@{user_id}> — {reason[:65]} ({active_count}/{cfg['warning_limit']} actifs, par {actor})"
                for at, user_id, username, reason, actor, consumed, expires_at, active_count in rows
            ) or "Aucun avertissement enregistré."
            body = (f"{prefix}Seuil : **{cfg['warning_limit']} avertissements sur {cfg['warning_window_days']} jours**.\n"
                    f"Après 5 avertissements : bans temporaires de {', '.join(str(days) + ' jours' for days in cfg['temporary_ban_days'])}. "
                    "Après 3 bans temporaires, la prochaine série de 5 avertissements entraîne le ban définitif.\n"
                    f"Avertissements automatiques : **{'activés' if cfg['auto_warning'] else 'désactivés'}**.\n\n"
                    f"**Derniers avertissements**\n{recent}\n\nUtilise /historique avertissements pour consulter le journal complet.")
            title = "⚠️ Avertissements"
        else:
            roles = ", ".join(f"<@&{value}>" for value in cfg["access_roles"][:12]) or "Aucun"
            users = ", ".join(f"<@{value}>" for value in cfg["access_users"][:12]) or "Aucun"
            selected_role = f"<@&{self.selected_role_id}>" if self.selected_role_id else "Aucun rôle sélectionné"
            selected_user = f"<@{self.selected_user_id}>" if self.selected_user_id else "Aucune personne sélectionnée"
            if cfg["access_control_enabled"]:
                policy = "Accès strict activé : seuls les administrateurs et les personnes/rôles listés peuvent utiliser les commandes protégées."
            else:
                policy = "Accès strict désactivé : les permissions Discord habituelles s'appliquent. Les personnes/rôles listés sont aussi autorisés."
            body = (f"{prefix}{policy}\n\n**Rôles autorisés**\n{roles}\n"
                    f"Sélection : {selected_role}\n\n**Personnes autorisées**\n{users}\n"
                    f"Sélection : {selected_user}\n\nChoisis un rôle ou une personne, puis utilise les boutons.\n"
                    "Les accès autorisés peuvent utiliser /sanction avertir et /sanction bannir. "
                    "Ils sont exclus des sanctions automatiques anti-spam.")
            title = "🔐 Accès au bot"
        embed = make_embed(title, body, 0x5865F2)
        embed.set_footer(text="SECURION · réglages enregistrés par serveur")
        return embed

    async def toggle_enabled(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["enabled"] = not cfg["enabled"]
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 2,
                     "État général des protections modifié", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def toggle_safe_mode(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["safe_mode"] = not cfg["safe_mode"]
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 2,
                     f"Mode prudent : {cfg['safe_mode']}", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def toggle_auto_warning(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["auto_warning"] = not cfg["auto_warning"]
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 2,
                     f"Avertissements automatiques : {cfg['auto_warning']}", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def toggle_auto_timeout(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["auto_timeout"] = not cfg["auto_timeout"]
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 2,
                     f"Timeout automatique : {cfg['auto_timeout']}", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def activate_auto_protection(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["enabled"] = True
        cfg["safe_mode"] = False
        cfg["auto_warning"] = True
        cfg["delete_triggering_message"] = True
        cfg["modules"]["anti_spam"] = True
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 3,
                     "Anti-spam, suppressions et avertissements automatiques activés", "par un administrateur")
        self.render()
        await interaction.response.edit_message(
            embed=self.make_embed("Anti-spam automatique réactivé."), view=self
        )

    async def toggle_module(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["modules"][self.selected_module] = not cfg["modules"].get(self.selected_module, True)
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 2,
                     f"Module {self.selected_module} : {cfg['modules'][self.selected_module]}", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def set_log_channel(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_modal(ChannelIdModal(self.guild_id, self.owner_id))

    async def clear_log_channel(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["log_channel_id"] = 0
        save_config(self.guild_id, cfg)
        self.render()
        await interaction.response.edit_message(embed=self.make_embed("Salon de logs retiré."), view=self)

    async def add_access_role(self, interaction: discord.Interaction) -> None:
        if not self.selected_role_id:
            return await send_private(interaction, "Choisis d'abord un rôle dans la liste.")
        if self.selected_role_id == interaction.guild.default_role.id:
            return await send_private(interaction, "Le rôle @everyone ne peut pas être autorisé.")
        cfg = get_config(self.guild_id)
        if self.selected_role_id not in cfg["access_roles"]:
            cfg["access_roles"].append(self.selected_role_id)
        cfg["access_control_enabled"] = True
        save_config(self.guild_id, cfg)
        self.render()
        await interaction.response.edit_message(embed=self.make_embed("Rôle autorisé."), view=self)

    async def remove_access_role(self, interaction: discord.Interaction) -> None:
        if not self.selected_role_id:
            return await send_private(interaction, "Choisis d'abord un rôle dans la liste.")
        cfg = get_config(self.guild_id)
        cfg["access_roles"] = [value for value in cfg["access_roles"] if value != self.selected_role_id]
        save_config(self.guild_id, cfg)
        self.render()
        await interaction.response.edit_message(embed=self.make_embed("Rôle retiré des accès."), view=self)

    async def add_access_user(self, interaction: discord.Interaction) -> None:
        if not self.selected_user_id:
            return await send_private(interaction, "Choisis d'abord une personne dans la liste.")
        cfg = get_config(self.guild_id)
        if self.selected_user_id not in cfg["access_users"]:
            cfg["access_users"].append(self.selected_user_id)
        cfg["access_control_enabled"] = True
        save_config(self.guild_id, cfg)
        self.render()
        await interaction.response.edit_message(embed=self.make_embed("Personne autorisée."), view=self)

    async def remove_access_user(self, interaction: discord.Interaction) -> None:
        if not self.selected_user_id:
            return await send_private(interaction, "Choisis d'abord une personne dans la liste.")
        cfg = get_config(self.guild_id)
        cfg["access_users"] = [value for value in cfg["access_users"] if value != self.selected_user_id]
        save_config(self.guild_id, cfg)
        self.render()
        await interaction.response.edit_message(embed=self.make_embed("Personne retirée des accès."), view=self)

    async def toggle_access_strict(self, interaction: discord.Interaction) -> None:
        cfg = get_config(self.guild_id)
        cfg["access_control_enabled"] = not cfg["access_control_enabled"]
        save_config(self.guild_id, cfg)
        record_event(self.guild_id, interaction.user.id, str(interaction.user), "configuration", 3,
                     f"Contrôle d'accès strict : {cfg['access_control_enabled']}", "par un administrateur")
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)


async def open_panel(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction, admin_only=True):
        return
    view = ConfigView(interaction.guild.id, interaction.user.id)
    await interaction.response.send_message(embed=view.make_embed(), view=view, ephemeral=True)


@bot.tree.command(name="panel", description="Ouvrir la configuration et les accès de SECURION")
@app_commands.default_permissions(manage_guild=True)
async def panel_command(interaction: discord.Interaction) -> None:
    await open_panel(interaction)


@bot.tree.command(name="configuration", description="Ouvrir le menu de réglage SECURION dans Discord")
@app_commands.default_permissions(manage_guild=True)
async def configuration(interaction: discord.Interaction) -> None:
    await open_panel(interaction)


@bot.tree.command(name="statut", description="Afficher l'état des protections SECURION")
async def status(interaction: discord.Interaction) -> None:
    if interaction.guild is None:
        return await send_private(interaction, "Cette commande doit être utilisée dans un serveur.")
    cfg = get_config(interaction.guild.id)
    if cfg["access_control_enabled"] and not has_command_access(interaction):
        return await send_private(interaction, "Tu n'as pas de rôle ou d'accès autorisé dans /panel.")
    active = sum(cfg["modules"].values())
    channel = f"<#{cfg['log_channel_id']}>" if cfg["log_channel_id"] else "non configuré"
    embed = make_embed("🛡️ État de SECURION",
        f"**Protections :** {'actives' if cfg['enabled'] else 'en pause'}\n"
        f"**Modules actifs :** {active}/{len(MODULE_LABELS)}\n"
        f"**Mode prudent :** {'activé' if cfg['safe_mode'] else 'désactivé'}\n"
        f"**Avertissements automatiques :** {'activés' if cfg['auto_warning'] else 'désactivés'}\n"
        f"**Timeout automatique :** {'activé' if cfg['auto_timeout'] else 'désactivé'}\n"
        f"**Sensibilité :** {cfg['global_level']}/10\n**Salon de logs :** {channel}",
        0x2ECC71 if cfg["enabled"] else 0xE74C3C)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="diagnostic", description="Vérifier la configuration anti-spam de SECURION")
@app_commands.default_permissions(manage_guild=True)
async def diagnostic(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction, admin_only=True):
        return
    guild = interaction.guild
    cfg = get_config(guild.id)
    me = guild.me

    if me is None:
        bot_permissions = None
    elif interaction.channel is not None and hasattr(interaction.channel, "permissions_for"):
        bot_permissions = interaction.channel.permissions_for(me)
    else:
        bot_permissions = None

    if not cfg["enabled"]:
        protection_state = "❌ Protections globales en pause. Réactive-les depuis /panel."
    else:
        protection_state = "✅ Protections globales actives."
    if not cfg["modules"].get("anti_spam", True):
        spam_state = "❌ Module anti-spam désactivé dans /panel."
    else:
        spam_state = "✅ Anti-spam actif : " + (
            f"{cfg['thresholds']['spam_count']} messages en {cfg['thresholds']['spam_seconds']} secondes."
        )
    safe_state = (
        "❌ Mode prudent activé : suppressions et avertissements automatiques coupés."
        if cfg["safe_mode"] else "✅ Mode prudent désactivé."
    )
    warning_state = (
        "✅ Avertissements automatiques activés."
        if cfg["auto_warning"] else "❌ Avertissements automatiques désactivés dans /panel."
    )
    ban_state = (
        "✅ SECURION a la permission Bannir des membres."
        if me is not None and me.guild_permissions.ban_members
        else "❌ Il manque la permission Bannir des membres pour les bans automatiques et manuels."
    )
    audit_state = (
        "✅ SECURION peut consulter le journal d'audit."
        if me is not None and me.guild_permissions.view_audit_log
        else "❌ Il manque Voir le journal d'audit pour surveiller les actions sensibles."
    )
    timeout_state = (
        "✅ SECURION peut appliquer les timeouts automatiques."
        if cfg["auto_timeout"] and me is not None and me.guild_permissions.moderate_members
        else "⚠️ Timeout automatique activé, mais la permission Modérer les membres manque."
        if cfg["auto_timeout"] else "ℹ️ Timeout automatique désactivé dans /panel."
    )
    if bot_permissions is None:
        channel_state = "⚠️ Permissions du salon actuel non vérifiables."
    elif not bot_permissions.view_channel:
        channel_state = "❌ SECURION ne peut pas lire les messages dans ce salon."
    elif bot_permissions.manage_messages:
        channel_state = "✅ SECURION peut lire et supprimer les messages dans ce salon."
    else:
        channel_state = "⚠️ SECURION peut lire ici, mais il manque Gérer les messages pour supprimer le spam."

    if me is None:
        coverage_state = "⚠️ Couverture des salons non vérifiable."
    else:
        monitored_channels = list(guild.text_channels)
        known_threads = list(getattr(guild, "threads", []) or [])
        monitored_channels.extend(known_threads)
        unreadable = [channel for channel in monitored_channels
                      if not channel.permissions_for(me).view_channel]
        undeletable = [channel for channel in monitored_channels
                       if channel.permissions_for(me).view_channel
                       and not channel.permissions_for(me).manage_messages]
        unreadable_sample = ", ".join(channel.mention for channel in unreadable[:4])
        undeletable_sample = ", ".join(channel.mention for channel in undeletable[:4])
        if unreadable:
            coverage_state = (
                f"❌ SECURION ne voit pas {len(unreadable)} salon(s) textuel(s) : {unreadable_sample}."
            )
        elif undeletable:
            coverage_state = (
                f"⚠️ Lecture possible dans les salons textuels et fils actifs connus, mais suppression impossible dans "
                f"{len(undeletable)} salon(s) : {undeletable_sample}."
            )
        else:
            coverage_state = "✅ SECURION peut voir et modérer les salons textuels et fils actifs connus."

    if me is None or not cfg["log_channel_id"]:
        log_state = "❌ Salon de logs non configuré : les alertes ne seront pas visibles."
    else:
        log_channel = guild.get_channel(cfg["log_channel_id"])
        if not isinstance(log_channel, (discord.TextChannel, discord.Thread)):
            log_state = "❌ Salon de logs introuvable : reconfigure-le dans /panel."
        else:
            log_permissions = log_channel.permissions_for(me)
            can_send = (
                log_permissions.send_messages_in_threads
                if isinstance(log_channel, discord.Thread)
                else log_permissions.send_messages
            )
            if log_permissions.view_channel and can_send:
                log_state = f"✅ SECURION peut envoyer les alertes dans {log_channel.mention}."
            else:
                log_state = f"❌ SECURION ne peut pas écrire dans {log_channel.mention}."

    if isinstance(interaction.user, discord.Member) and is_exempt(interaction.user, cfg):
        test_state = (
            "⚠️ Ton compte est exempté de la détection automatique (staff, accès autorisé ou liste blanche). "
            "Teste avec un membre ordinaire."
        )
    else:
        test_state = "✅ Ton compte n'est pas exempté de la détection automatique."
    intent_state = (
        "Intent Message Content demandé par le code : vérifie aussi qu'il est activé dans le Developer Portal."
        if bot.intents.message_content else "❌ Intent Message Content désactivé dans le code."
    )
    member_intent_state = (
        "Intent Server Members demandé par le code : vérifie aussi qu'il est activé dans le Developer Portal."
        if bot.intents.members else "❌ Intent Server Members désactivé dans le code."
    )
    guild_message_state = (
        "✅ Événements de messages des serveurs activés dans le code."
        if bot.intents.guild_messages else "❌ Événements de messages des serveurs désactivés dans le code."
    )
    description = "\n".join((
        protection_state, spam_state, safe_state, warning_state, ban_state, audit_state, timeout_state,
        channel_state, coverage_state, log_state, test_state, guild_message_state,
        intent_state, member_intent_state,
        "\nPour tester : avec un compte ordinaire, envoie au moins "
        f"{cfg['thresholds']['spam_count']} messages en moins de "
        f"{cfg['thresholds']['spam_seconds']} secondes dans ce serveur. "
        "Le rôle de SECURION doit être au-dessus du membre à bannir.",
    ))
    embed = make_embed("🔎 Diagnostic SECURION", description, 0x5865F2)
    embed.set_footer(text=f"SECURION {VERSION}")
    await interaction.response.send_message(embed=embed, ephemeral=True)


protection = app_commands.Group(name="protection", description="Régler les protections de SECURION")


@protection.command(name="pause", description="Mettre les protections de ce serveur en pause")
@app_commands.default_permissions(manage_guild=True)
async def protection_pause(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["enabled"] = False
    save_config(interaction.guild.id, cfg)
    record_event(interaction.guild.id, interaction.user.id, str(interaction.user), "configuration", 2,
                 "Protections mises en pause", "par un administrateur")
    await send_private(interaction, "Les protections SECURION sont en pause sur ce serveur.")


@protection.command(name="reprendre", description="Réactiver les protections de ce serveur")
@app_commands.default_permissions(manage_guild=True)
async def protection_resume(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["enabled"] = True
    save_config(interaction.guild.id, cfg)
    record_event(interaction.guild.id, interaction.user.id, str(interaction.user), "configuration", 2,
                 "Protections réactivées", "par un administrateur")
    await send_private(interaction, "Les protections SECURION sont réactivées.")


@protection.command(name="prudent", description="Activer ou désactiver le mode prudent")
@app_commands.default_permissions(manage_guild=True)
async def protection_safe(interaction: discord.Interaction, actif: bool) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["safe_mode"] = actif
    save_config(interaction.guild.id, cfg)
    record_event(interaction.guild.id, interaction.user.id, str(interaction.user), "configuration", 2,
                 f"Mode prudent réglé sur {actif}", "par un administrateur")
    text = "activé : les détections journalisent sans sanction automatique." if actif else "désactivé."
    await send_private(interaction, f"Mode prudent {text}")


@protection.command(name="timeout_auto", description="Autoriser ou couper le timeout automatique pour le spam grave")
@app_commands.default_permissions(manage_guild=True)
async def protection_auto_timeout(interaction: discord.Interaction, actif: bool) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["auto_timeout"] = actif
    save_config(interaction.guild.id, cfg)
    status = "activé" if actif else "désactivé"
    if actif and cfg["safe_mode"]:
        status += " (inactif tant que le mode prudent reste activé)"
    record_event(interaction.guild.id, interaction.user.id, str(interaction.user), "configuration", 2,
                 f"Timeout automatique : {actif}", "par un administrateur")
    await send_private(interaction, f"Timeout automatique {status}.")


@protection.command(name="niveau", description="Régler la sensibilité de 1 à 10")
@app_commands.default_permissions(manage_guild=True)
async def protection_level(interaction: discord.Interaction, niveau: app_commands.Range[int, 1, 10]) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["global_level"] = int(niveau)
    save_config(interaction.guild.id, cfg)
    await send_private(interaction, f"Sensibilité réglée sur {niveau}/10.")


@protection.command(name="module", description="Activer ou désactiver un module de sécurité")
@app_commands.default_permissions(manage_guild=True)
@app_commands.choices(module=[app_commands.Choice(name=label, value=key) for key, label in MODULE_LABELS.items()])
async def protection_module(interaction: discord.Interaction, module: app_commands.Choice[str], actif: bool) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    cfg["modules"][module.value] = actif
    save_config(interaction.guild.id, cfg)
    await send_private(interaction, f"{MODULE_LABELS[module.value]} est maintenant {'activé' if actif else 'désactivé'}.")


bot.tree.add_command(protection)


sanction = app_commands.Group(name="sanction", description="Modérer un membre du serveur")


@sanction.command(name="avertir", description="Enregistrer un avertissement pour un membre")
async def sanction_warn(interaction: discord.Interaction, membre: discord.Member, motif: str) -> None:
    if await reject_permission(interaction, "moderate_members"):
        return
    reason = motif.strip()[:500]
    if not reason:
        return await send_private(interaction, "Indique le motif de l'avertissement.")
    if is_exempt(membre, get_config(interaction.guild.id)):
        return await send_private(interaction, "Ce membre est protégé par son rôle de staff ou la liste blanche.")
    result = await issue_warning(membre, reason, str(interaction.user), allow_escalation=True)
    message = f"Avertissement {result['count']}/{result['limit']} enregistré pour {membre.display_name}."
    if result["sanction"]:
        message += " " + result["sanction"]["message"]
    if not result["dm_sent"]:
        message += " Le message privé n'a pas pu être envoyé."
    await send_private(interaction, message)


@sanction.command(name="timeout", description="Mettre un membre en timeout")
async def sanction_timeout(interaction: discord.Interaction, membre: discord.Member,
                           minutes: app_commands.Range[int, 1, 40320], motif: str) -> None:
    if await reject_permission(interaction, "moderate_members"):
        return
    allowed, message = await can_bot_moderate(interaction.guild, membre)
    if not allowed:
        return await send_private(interaction, message)
    if is_exempt(membre, get_config(interaction.guild.id)):
        return await send_private(interaction, "Ce membre est protégé par son rôle de staff ou la liste blanche.")
    reason = motif.strip()[:500] or "Aucun motif indiqué"
    try:
        await membre.timeout(discord.utils.utcnow() + timedelta(minutes=int(minutes)),
                             reason=f"SECURION · {interaction.user} · {reason}"[:500])
    except discord.Forbidden:
        return await send_private(interaction, "Discord a refusé le timeout. Vérifie les permissions et la hiérarchie du rôle de SECURION.")
    except discord.HTTPException:
        return await send_private(interaction, "Discord n'a pas pu appliquer le timeout.")
    record_event(interaction.guild.id, membre.id, str(membre), "timeout", 6, reason,
                 f"{minutes} minute(s) · par {interaction.user}")
    await send_log(interaction.guild, f"⏱️ **Timeout** · {membre.mention} ({membre.id})\nDurée : {minutes} minute(s)\nMotif : {reason}\nPar : {interaction.user}")
    await send_private(interaction, f"Timeout appliqué à {membre.display_name} pour {minutes} minute(s).")


@sanction.command(name="expulser", description="Expulser un membre du serveur")
async def sanction_kick(interaction: discord.Interaction, membre: discord.Member, motif: str) -> None:
    if await reject_permission(interaction, "kick_members"):
        return
    allowed, message = await can_bot_moderate(interaction.guild, membre)
    if not allowed:
        return await send_private(interaction, message)
    reason = motif.strip()[:500] or "Aucun motif indiqué"
    try:
        await membre.kick(reason=f"SECURION · {interaction.user} · {reason}"[:500])
    except discord.Forbidden:
        return await send_private(interaction, "Discord a refusé l'expulsion. Vérifie les permissions et la hiérarchie du rôle de SECURION.")
    except discord.HTTPException:
        return await send_private(interaction, "Discord n'a pas pu expulser ce membre.")
    record_event(interaction.guild.id, membre.id, str(membre), "expulsion", 8, reason, f"par {interaction.user}")
    await send_log(interaction.guild, f"👢 **Expulsion** · {membre} ({membre.id})\nMotif : {reason}\nPar : {interaction.user}")
    await send_private(interaction, f"{membre} a été expulsé.")


@sanction.command(name="bannir", description="Bannir un membre du serveur")
async def sanction_ban(interaction: discord.Interaction, membre: discord.Member, motif: str) -> None:
    if await reject_permission(interaction, "ban_members"):
        return
    allowed, message = await can_bot_moderate(interaction.guild, membre)
    if not allowed:
        return await send_private(interaction, message)
    reason = motif.strip()[:500] or "Aucun motif indiqué"
    dm_sent = await dm_member(
        membre,
        f"SECURION va appliquer un bannissement définitif sur {interaction.guild.name}.\n"
        f"Motif : {reason}\nSi tu penses qu'il s'agit d'une erreur, contacte l'équipe du serveur.",
    )
    try:
        await interaction.guild.ban(membre, reason=f"SECURION · {interaction.user} · {reason}"[:500],
                                    delete_message_seconds=0)
    except discord.Forbidden:
        if dm_sent:
            await dm_member(membre, "Le bannissement annoncé par SECURION n'a finalement pas pu être appliqué.")
        return await send_private(interaction, "Discord a refusé le bannissement. Vérifie les permissions et la hiérarchie du rôle de SECURION.")
    except discord.HTTPException:
        if dm_sent:
            await dm_member(membre, "Le bannissement annoncé par SECURION n'a finalement pas pu être appliqué.")
        return await send_private(interaction, "Discord n'a pas pu bannir ce membre.")
    record_event(interaction.guild.id, membre.id, str(membre), "bannissement", 10, reason, f"par {interaction.user}")
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        con.execute(
            "INSERT INTO sanctions(guild_id,user_id,username,kind,reason,actor,created_at,expires_at,status) "
            "VALUES(?,?,?,?,?,?,?,NULL,'active')",
            (interaction.guild.id, membre.id, str(membre)[:100], "manual", reason[:500],
             str(interaction.user)[:100], utc_now_iso()),
        )
    dm_status = "message privé envoyé" if dm_sent else "message privé impossible (MP fermés ou indisponibles)"
    await send_log(interaction.guild, f"⛔ **Bannissement** · {membre} ({membre.id})\nMotif : {reason}\nPar : {interaction.user}\n{dm_status}")
    await send_private(interaction, f"{membre} a été banni ; {dm_status}.")


@sanction.command(name="debannir", description="Débannir avec l'identifiant Discord de l'utilisateur")
async def sanction_unban(interaction: discord.Interaction, identifiant: str,
                         motif: str = "Débannissement demandé par le staff") -> None:
    if await reject_permission(interaction, "ban_members"):
        return
    if not identifiant.isdigit() or not 0 < int(identifiant) < 2**64:
        return await send_private(interaction, "Indique un identifiant Discord valide.")
    user_id = int(identifiant)
    try:
        await interaction.guild.unban(discord.Object(id=user_id),
                                      reason=f"SECURION · {interaction.user} · {motif}"[:500])
    except discord.NotFound:
        return await send_private(interaction, "Aucun bannissement actif trouvé pour cet identifiant.")
    except discord.Forbidden:
        return await send_private(interaction, "Discord a refusé le débannissement. Vérifie la permission Bannir des membres.")
    except discord.HTTPException:
        return await send_private(interaction, "Discord n'a pas pu lever ce bannissement.")
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        con.execute(
            "UPDATE sanctions SET status='unbanned' WHERE guild_id=? AND user_id=? AND status='active'",
            (interaction.guild.id, user_id),
        )
    record_event(interaction.guild.id, user_id, identifiant, "débannissement", 2, motif[:500], f"par {interaction.user}")
    await send_log(interaction.guild, f"✅ **Débannissement** · {user_id}\nMotif : {motif}\nPar : {interaction.user}")
    await send_private(interaction, f"L'utilisateur {user_id} a été débanni.")


bot.tree.add_command(sanction)


class HistorySectionSelect(discord.ui.Select):
    def __init__(self, view: "HistoryActionsView"):
        self.actions_view = view
        options = [
            discord.SelectOption(label="Avertissements", value="warnings", emoji="⚠️",
                                 default=view.section == "warnings"),
            discord.SelectOption(label="Timeouts", value="timeouts", emoji="⏱️",
                                 default=view.section == "timeouts"),
            discord.SelectOption(label="Bannissements", value="bans", emoji="🔨",
                                 default=view.section == "bans"),
        ]
        super().__init__(placeholder="Choisir une action d'historique", options=options,
                         min_values=1, max_values=1, row=0)

    async def callback(self, interaction: discord.Interaction) -> None:
        view = self.actions_view
        view.section = self.values[0]
        if view.section == "bans":
            await interaction.response.defer()
            await view.load_bans(interaction.guild)
            view.render()
            await interaction.edit_original_response(embed=view.make_embed(), view=view)
            return
        view.render()
        await interaction.response.edit_message(embed=view.make_embed(), view=view)


class HistoryMemberSelect(discord.ui.UserSelect):
    def __init__(self, view: "HistoryActionsView"):
        self.actions_view = view
        placeholder = "Choisir la personne concernée"
        super().__init__(placeholder=placeholder, min_values=1, max_values=1, row=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        member = self.values[0]
        if not isinstance(member, discord.Member):
            return await send_private(interaction, "Choisis une personne de ce serveur.")
        self.actions_view.selected_member_id = member.id
        self.actions_view.selected_warning_id = None
        self.actions_view.warning_page = 0
        self.actions_view.render()
        await interaction.response.edit_message(
            embed=self.actions_view.make_embed("Personne sélectionnée."), view=self.actions_view
        )


class HistoryWarningSelect(discord.ui.Select):
    def __init__(self, view: "HistoryActionsView", rows: list[tuple[Any, ...]]):
        self.actions_view = view
        options = []
        for warning_id, created_at, reason, actor in rows:
            safe_reason = str(reason).replace("\n", " ").replace("\r", " ")
            label = f"{created_at[:16]} · {safe_reason}"[:100]
            description = f"Par {actor}"[:100]
            options.append(discord.SelectOption(
                label=label, value=str(warning_id), description=description,
                default=int(warning_id) == view.selected_warning_id,
            ))
        super().__init__(placeholder="Choisir l'avertissement à retirer", options=options,
                         min_values=1, max_values=1, row=2)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.actions_view.selected_warning_id = int(self.values[0])
        self.actions_view.render()
        await interaction.response.edit_message(embed=self.actions_view.make_embed(), view=self.actions_view)


class HistoryBanSelect(discord.ui.Select):
    def __init__(self, view: "HistoryActionsView", entries: list[Any]):
        self.actions_view = view
        start = view.ban_page * 25
        page_entries = entries[start:start + 25]
        options = []
        for entry in page_entries:
            user = entry.user
            safe_username = str(user).replace("\n", " ").replace("\r", " ")
            label = f"{safe_username} · {user.id}"[:100]
            reason = (entry.reason or "Aucun motif enregistré").replace("\n", " ")
            options.append(discord.SelectOption(
                label=label, value=str(user.id), description=reason[:100],
                default=user.id == view.selected_ban_user_id,
            ))
        super().__init__(placeholder="Choisir une personne bannie", options=options,
                         min_values=1, max_values=1, row=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.actions_view.selected_ban_user_id = int(self.values[0])
        self.actions_view.render()
        await interaction.response.edit_message(embed=self.actions_view.make_embed(), view=self.actions_view)


class HistoryActionsView(discord.ui.View):
    def __init__(self, guild_id: int, owner_id: int, selected_member_id: int | None = None):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        self.owner_id = owner_id
        self.selected_member_id = selected_member_id
        self.selected_warning_id: int | None = None
        self.selected_ban_user_id: int | None = None
        self.section = "warnings"
        self.warning_page = 0
        self.warning_count = 0
        self.ban_page = 0
        self.bans: list[Any] = []
        self.ban_load_error = ""
        self.render()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Lance /historique actions pour ouvrir ton propre menu.", ephemeral=True)
            return False
        if interaction.guild is None or interaction.guild.id != self.guild_id:
            await interaction.response.send_message("Ce menu ne correspond pas à ce serveur.", ephemeral=True)
            return False
        return True

    def _button(self, label: str, style: discord.ButtonStyle, callback,
                row: int, *, disabled: bool = False) -> discord.ui.Button:
        button = discord.ui.Button(label=label, style=style, row=row, disabled=disabled)
        button.callback = callback
        return button

    def active_warning_page(self) -> list[tuple[Any, ...]]:
        if not self.selected_member_id:
            self.warning_count = 0
            return []
        now = utc_now_iso()
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            self.warning_count = int(con.execute(
                "SELECT COUNT(*) FROM warnings WHERE guild_id=? AND user_id=? "
                "AND consumed=0 AND removed=0 AND expires_at>?",
                (self.guild_id, self.selected_member_id, now),
            ).fetchone()[0])
            self.warning_page = min(self.warning_page, max(0, (self.warning_count - 1) // 25))
            return con.execute(
                "SELECT id,created_at,reason,actor FROM warnings WHERE guild_id=? AND user_id=? "
                "AND consumed=0 AND removed=0 AND expires_at>? ORDER BY id DESC LIMIT 25 OFFSET ?",
                (self.guild_id, self.selected_member_id, now, self.warning_page * 25),
            ).fetchall()

    async def load_bans(self, guild: discord.Guild) -> None:
        try:
            self.bans = [entry async for entry in guild.bans(limit=None)]
            self.ban_load_error = ""
        except discord.Forbidden:
            self.bans = []
            self.ban_load_error = "SECURION doit avoir la permission Bannir des membres pour afficher la liste des bans."
        except discord.HTTPException:
            self.bans = []
            self.ban_load_error = "Discord n'a pas pu charger les bannissements. Réessaie dans un instant."

    def render(self) -> "HistoryActionsView":
        self.clear_items()
        self.add_item(HistorySectionSelect(self))
        if self.section == "warnings":
            self.add_item(HistoryMemberSelect(self))
            rows = self.active_warning_page()
            if rows:
                self.add_item(HistoryWarningSelect(self, rows))
                pages = max(1, (self.warning_count + 24) // 25)
                if pages > 1:
                    self.add_item(self._button("Précédent", discord.ButtonStyle.secondary,
                                               self.previous_warning_page, 3,
                                               disabled=self.warning_page <= 0))
                    self.add_item(self._button("Suivant", discord.ButtonStyle.secondary,
                                               self.next_warning_page, 3,
                                               disabled=self.warning_page >= pages - 1))
                self.add_item(self._button("Retirer cet avertissement", discord.ButtonStyle.secondary,
                                           self.remove_selected_warning, 4,
                                           disabled=self.selected_warning_id is None))
            if self.selected_member_id:
                self.add_item(self._button("Réinitialiser le compteur", discord.ButtonStyle.danger,
                                           self.reset_warning_counter, 4))
        elif self.section == "timeouts":
            self.add_item(HistoryMemberSelect(self))
            if self.selected_member_id:
                self.add_item(self._button("Retirer le timeout", discord.ButtonStyle.danger,
                                           self.clear_timeout, 2))
        elif self.section == "bans":
            if self.bans:
                self.add_item(HistoryBanSelect(self, self.bans))
                pages = max(1, (len(self.bans) + 24) // 25)
                if pages > 1:
                    self.add_item(self._button("Précédent", discord.ButtonStyle.secondary,
                                               self.previous_ban_page, 2,
                                               disabled=self.ban_page <= 0))
                    self.add_item(self._button("Suivant", discord.ButtonStyle.secondary,
                                               self.next_ban_page, 2,
                                               disabled=self.ban_page >= pages - 1))
                self.add_item(self._button("Débannir la personne sélectionnée", discord.ButtonStyle.danger,
                                           self.unban_selected, 3,
                                           disabled=self.selected_ban_user_id is None))
        return self

    def make_embed(self, notice: str = "") -> discord.Embed:
        prefix = f"{notice}\n\n" if notice else ""
        if self.section == "warnings":
            cfg = get_config(self.guild_id)
            if self.selected_member_id:
                pages = max(1, (self.warning_count + 24) // 25)
                body = (f"{prefix}Personne : <@{self.selected_member_id}> (`{self.selected_member_id}`).\n"
                        f"Avertissements actifs : **{self.warning_count}/{cfg['warning_limit']}**.\n"
                        "Choisis un avertissement pour le retirer, ou réinitialise le compteur pour enlever tous les avertissements actifs.\n"
                        f"Page : {self.warning_page + 1}/{pages}.")
            else:
                body = f"{prefix}Sélectionne une personne du serveur pour afficher et gérer ses avertissements actifs."
            title = "⚠️ Gérer les avertissements"
        elif self.section == "timeouts":
            if self.selected_member_id:
                body = (f"{prefix}Personne : <@{self.selected_member_id}> (`{self.selected_member_id}`).\n"
                        "Utilise le bouton pour retirer son timeout Discord, s'il est encore actif.")
            else:
                body = f"{prefix}Sélectionne une personne du serveur pour retirer son timeout."
            title = "⏱️ Gérer les timeouts"
        else:
            if self.ban_load_error:
                body = f"{prefix}{self.ban_load_error}"
            elif not self.bans:
                body = f"{prefix}Aucun bannissement actif trouvé dans ce serveur."
            else:
                pages = max(1, (len(self.bans) + 24) // 25)
                selected = (f"Personne sélectionnée : `{self.selected_ban_user_id}`.\n"
                            if self.selected_ban_user_id else "Sélectionne une personne dans la liste.\n")
                body = (f"{prefix}{len(self.bans)} bannissement(s) actif(s) trouvés.\n"
                        f"{selected}Page : {self.ban_page + 1}/{pages}. Le bouton Débannir lève le ban immédiatement.")
            title = "🔨 Gérer les bannissements"
        embed = make_embed(title, body, 0x5865F2)
        embed.set_footer(text=f"SECURION {VERSION} · actions réservées au staff autorisé")
        return embed

    async def _refresh_message(self, interaction: discord.Interaction, notice: str = "") -> None:
        self.render()
        await interaction.edit_original_response(embed=self.make_embed(notice), view=self)

    async def previous_warning_page(self, interaction: discord.Interaction) -> None:
        self.warning_page = max(0, self.warning_page - 1)
        self.selected_warning_id = None
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def next_warning_page(self, interaction: discord.Interaction) -> None:
        pages = max(1, (self.warning_count + 24) // 25)
        self.warning_page = min(pages - 1, self.warning_page + 1)
        self.selected_warning_id = None
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def previous_ban_page(self, interaction: discord.Interaction) -> None:
        self.ban_page = max(0, self.ban_page - 1)
        self.selected_ban_user_id = None
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def next_ban_page(self, interaction: discord.Interaction) -> None:
        pages = max(1, (len(self.bans) + 24) // 25)
        self.ban_page = min(pages - 1, self.ban_page + 1)
        self.selected_ban_user_id = None
        self.render()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    async def remove_selected_warning(self, interaction: discord.Interaction) -> None:
        if await reject_permission(interaction, "moderate_members"):
            return
        if not self.selected_member_id or not self.selected_warning_id:
            return await send_private(interaction, "Choisis une personne et un avertissement actif.")
        await interaction.response.defer()
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            row = con.execute(
                "SELECT reason FROM warnings WHERE id=? AND guild_id=? AND user_id=? "
                "AND consumed=0 AND removed=0 AND expires_at>?",
                (self.selected_warning_id, self.guild_id, self.selected_member_id, utc_now_iso()),
            ).fetchone()
            if row:
                con.execute("UPDATE warnings SET removed=1 WHERE id=?", (self.selected_warning_id,))
        if not row:
            return await self._refresh_message(interaction, "Cet avertissement n'est plus actif.")
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            self.warning_count = int(con.execute(
                "SELECT COUNT(*) FROM warnings WHERE guild_id=? AND user_id=? "
                "AND consumed=0 AND removed=0 AND expires_at>?",
                (self.guild_id, self.selected_member_id, utc_now_iso()),
            ).fetchone()[0])
        self.warning_page = min(self.warning_page, max(0, (self.warning_count - 1) // 25))
        guild = interaction.guild
        member = guild.get_member(self.selected_member_id)
        username = str(member) if member else str(self.selected_member_id)
        record_event(self.guild_id, self.selected_member_id, username, "avertissement retiré", 2,
                     str(row[0]), f"par {interaction.user}")
        await send_log(guild, f"🧹 **Avertissement retiré** · {username} ({self.selected_member_id})\n"
                       f"Motif : {row[0]}\nPar : {interaction.user}")
        self.selected_warning_id = None
        await self._refresh_message(interaction, "Avertissement retiré de son compteur.")

    async def reset_warning_counter(self, interaction: discord.Interaction) -> None:
        if await reject_permission(interaction, "moderate_members"):
            return
        if not self.selected_member_id:
            return await send_private(interaction, "Choisis d'abord une personne.")
        await interaction.response.defer()
        now = utc_now_iso()
        with sqlite3.connect(DB_PATH, timeout=10) as con:
            cursor = con.execute(
                "UPDATE warnings SET removed=1 WHERE guild_id=? AND user_id=? "
                "AND consumed=0 AND removed=0 AND expires_at>?",
                (self.guild_id, self.selected_member_id, now),
            )
            removed_count = cursor.rowcount
        guild = interaction.guild
        member = guild.get_member(self.selected_member_id)
        username = str(member) if member else str(self.selected_member_id)
        record_event(self.guild_id, self.selected_member_id, username, "compteur d'avertissements réinitialisé", 2,
                     f"{removed_count} avertissement(s) actif(s) retiré(s)", f"par {interaction.user}")
        await send_log(guild, f"🧹 **Compteur réinitialisé** · {username} ({self.selected_member_id})\n"
                       f"{removed_count} avertissement(s) actif(s) retiré(s) par {interaction.user}.")
        self.selected_warning_id = None
        self.warning_page = 0
        await self._refresh_message(interaction, f"Compteur remis à zéro : {removed_count} avertissement(s) actif(s) retiré(s).")

    async def clear_timeout(self, interaction: discord.Interaction) -> None:
        if await reject_permission(interaction, "moderate_members"):
            return
        if not self.selected_member_id:
            return await send_private(interaction, "Choisis d'abord une personne du serveur.")
        guild = interaction.guild
        me = guild.me
        if me is None or not me.guild_permissions.moderate_members:
            return await send_private(interaction, "SECURION doit avoir la permission Modérer les membres.")
        member = guild.get_member(self.selected_member_id)
        if member is None:
            try:
                member = await guild.fetch_member(self.selected_member_id)
            except discord.NotFound:
                return await send_private(interaction, "Cette personne n'est plus dans le serveur.")
            except (discord.Forbidden, discord.HTTPException):
                return await send_private(interaction, "Discord n'a pas pu retrouver cette personne.")
        allowed, message = await can_bot_moderate(guild, member)
        if not allowed:
            return await send_private(interaction, message)
        await interaction.response.defer()
        try:
            await member.timeout(None, reason=f"SECURION · timeout retiré par {interaction.user}"[:500])
        except discord.Forbidden:
            return await self._refresh_message(interaction, "Discord a refusé de retirer le timeout. Vérifie les permissions et la hiérarchie du rôle.")
        except discord.HTTPException:
            return await self._refresh_message(interaction, "Discord n'a pas pu retirer le timeout. Réessaie.")
        record_event(guild.id, member.id, str(member), "timeout retiré", 2,
                     "Timeout Discord retiré depuis /historique actions", f"par {interaction.user}")
        await send_log(guild, f"✅ **Timeout retiré** · {member} ({member.id})\nPar : {interaction.user}")
        await self._refresh_message(interaction, f"Timeout retiré pour {member.display_name}.")

    async def unban_selected(self, interaction: discord.Interaction) -> None:
        if await reject_permission(interaction, "ban_members"):
            return
        if self.selected_ban_user_id is None:
            return await send_private(interaction, "Choisis d'abord une personne bannie dans la liste.")
        guild = interaction.guild
        me = guild.me
        if me is None or not me.guild_permissions.ban_members:
            return await send_private(interaction, "SECURION doit avoir la permission Bannir des membres pour débannir.")
        user_id = self.selected_ban_user_id
        entry = next((item for item in self.bans if item.user.id == user_id), None)
        username = str(entry.user) if entry else str(user_id)
        await interaction.response.defer()
        notice = f"{username} a été débanni."
        try:
            await guild.unban(discord.Object(id=user_id), reason=f"SECURION · débanni par {interaction.user}"[:500])
        except discord.NotFound:
            notice = f"{username} n'est déjà plus banni. Liste actualisée."
            await self.load_bans(guild)
        except discord.Forbidden:
            return await self._refresh_message(interaction, "Discord a refusé le débannissement. Vérifie les permissions du bot.")
        except discord.HTTPException:
            return await self._refresh_message(interaction, "Discord n'a pas pu débannir cette personne. Réessaie.")
        else:
            self.ban_load_error = ""
            record_event(guild.id, user_id, username, "débannissement", 2,
                         "Bannissement levé depuis /historique actions", f"par {interaction.user}")
            try:
                with sqlite3.connect(DB_PATH, timeout=10) as con:
                    con.execute(
                        "UPDATE sanctions SET status='unbanned' WHERE guild_id=? AND user_id=? AND status='active'",
                        (guild.id, user_id),
                    )
            except sqlite3.Error:
                log.exception("Bannissement levé mais impossible de mettre l'historique à jour pour %s", user_id)
            await send_log(guild, f"✅ **Débannissement** · {username} ({user_id})\nPar : {interaction.user}")
        if not self.ban_load_error:
            self.bans = [item for item in self.bans if item.user.id != user_id]
        self.selected_ban_user_id = None
        self.ban_page = min(self.ban_page, max(0, (len(self.bans) - 1) // 25))
        await self._refresh_message(interaction, notice if not self.ban_load_error else self.ban_load_error)


class HistoryActionsLauncher(discord.ui.View):
    def __init__(self, guild_id: int, owner_id: int, member_id: int | None = None):
        super().__init__(timeout=180)
        self.guild_id = guild_id
        self.owner_id = owner_id
        self.member_id = member_id
        button = discord.ui.Button(label="Gérer les avertissements, timeouts et bans",
                                   style=discord.ButtonStyle.primary)
        button.callback = self.open_actions
        self.add_item(button)

    async def open_actions(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != self.owner_id or interaction.guild is None or interaction.guild.id != self.guild_id:
            return await send_private(interaction, "Relance la commande /historique pour ouvrir ton propre menu.")
        if await reject_permission(interaction, "moderate_members"):
            return
        view = HistoryActionsView(self.guild_id, self.owner_id, self.member_id)
        await interaction.response.send_message(embed=view.make_embed(), view=view, ephemeral=True)


historique = app_commands.Group(name="historique", description="Consulter le journal et gérer les sanctions")


@historique.command(name="actions", description="Retirer des avertissements, timeout ou ban")
async def history_actions(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction, "moderate_members"):
        return
    view = HistoryActionsView(interaction.guild.id, interaction.user.id)
    await interaction.response.send_message(embed=view.make_embed(), view=view, ephemeral=True)


@historique.command(name="membre", description="Afficher et gérer l'historique d'un membre")
async def history_member(interaction: discord.Interaction, membre: discord.Member) -> None:
    if await reject_permission(interaction, "moderate_members"):
        return
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        rows = con.execute(
            "SELECT at,kind,severity,detail,action FROM events WHERE guild_id=? AND user_id=? ORDER BY id DESC LIMIT 10",
            (interaction.guild.id, membre.id),
        ).fetchall()
    description = f"Identifiant : {membre.id}"
    if not rows:
        description += "\nAucun événement enregistré pour cette personne."
    embed = make_embed(f"📜 Historique · {membre}", description, 0x5865F2)
    for at, kind, severity, detail, action in rows:
        embed.add_field(name=f"{at} · {kind} · gravité {severity}/10",
                        value=f"{detail or 'Aucun détail'}\nAction : {action or 'journalisée'}"[:1024],
                        inline=False)
    view = HistoryActionsLauncher(interaction.guild.id, interaction.user.id, membre.id)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@historique.command(name="avertissements", description="Voir et gérer les avertissements récents")
async def history_warnings(
    interaction: discord.Interaction,
    membre: discord.Member | None = None,
    limite: app_commands.Range[int, 1, 20] = 10,
) -> None:
    if await reject_permission(interaction, "moderate_members"):
        return
    query = (
        "SELECT created_at,user_id,username,reason,actor,consumed,expires_at,removed FROM warnings "
        "WHERE guild_id=?"
    )
    params: list[Any] = [interaction.guild.id]
    if membre is not None:
        query += " AND user_id=?"
        params.append(membre.id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limite))
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        rows = con.execute(query, params).fetchall()
    title = f"⚠️ Avertissements · {membre}" if membre else "⚠️ Avertissements récents"
    embed = make_embed(title, f"Derniers {len(rows)} avertissements enregistrés." if rows else "Aucun avertissement trouvé.", 0xE69B00)
    now = utc_now_iso()
    for created, user_id, username, reason, actor, consumed, expires_at, removed in rows:
        if removed:
            state = "retiré par le staff"
        elif consumed:
            state = "consommé lors d'une sanction"
        else:
            state = "expiré" if expires_at <= now else "actif"
        name = f"{created} · {username} ({user_id}) · {state}"
        value = f"Motif : {reason}\nPar : {actor}"
        embed.add_field(name=name[:256], value=value[:1024], inline=False)
    view = HistoryActionsLauncher(interaction.guild.id, interaction.user.id, membre.id if membre else None)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


bot.tree.add_command(historique)


whitelist = app_commands.Group(name="wl", description="Gérer la liste blanche SECURION")


@whitelist.command(name="ajouter", description="Exempter un membre ou un rôle des protections")
@app_commands.default_permissions(manage_guild=True)
async def whitelist_add(interaction: discord.Interaction, membre: discord.Member | None = None,
                        role: discord.Role | None = None) -> None:
    if await reject_permission(interaction):
        return
    if (membre is None) == (role is None):
        return await send_private(interaction, "Choisis exactement un membre ou un rôle.")
    cfg = get_config(interaction.guild.id)
    if membre:
        if membre.id not in cfg["whitelist_users"]:
            cfg["whitelist_users"].append(membre.id)
        name, item_id = membre.mention, membre.id
    else:
        if role.id == interaction.guild.default_role.id:
            return await send_private(interaction, "Le rôle @everyone ne peut pas être ajouté à la liste blanche.")
        if role.id not in cfg["whitelist_roles"]:
            cfg["whitelist_roles"].append(role.id)
        name, item_id = role.mention, role.id
    save_config(interaction.guild.id, cfg)
    record_event(interaction.guild.id, item_id, name, "liste blanche", 1, "Ajout à la liste blanche", f"par {interaction.user}")
    await send_private(interaction, f"{name} a été ajouté à la liste blanche.")


@whitelist.command(name="retirer", description="Retirer un membre ou rôle de la liste blanche")
@app_commands.default_permissions(manage_guild=True)
async def whitelist_remove(interaction: discord.Interaction, membre: discord.Member | None = None,
                           role: discord.Role | None = None) -> None:
    if await reject_permission(interaction):
        return
    if (membre is None) == (role is None):
        return await send_private(interaction, "Choisis exactement un membre ou un rôle.")
    cfg = get_config(interaction.guild.id)
    if membre:
        cfg["whitelist_users"] = [value for value in cfg["whitelist_users"] if value != membre.id]
        name = membre.mention
    else:
        cfg["whitelist_roles"] = [value for value in cfg["whitelist_roles"] if value != role.id]
        name = role.mention
    save_config(interaction.guild.id, cfg)
    await send_private(interaction, f"{name} a été retiré de la liste blanche.")


@whitelist.command(name="liste", description="Afficher les membres et rôles exemptés")
@app_commands.default_permissions(manage_guild=True)
async def whitelist_list(interaction: discord.Interaction) -> None:
    if await reject_permission(interaction):
        return
    cfg = get_config(interaction.guild.id)
    users = [f"<@{value}>" for value in cfg["whitelist_users"][:40]] or ["Aucun"]
    roles = [f"<@&{value}>" for value in cfg["whitelist_roles"][:40]] or ["Aucun"]
    embed = make_embed("✅ Liste blanche",
                       f"**Membres**\n{', '.join(users)}\n\n**Rôles**\n{', '.join(roles)}", 0x5865F2)
    await interaction.response.send_message(embed=embed, ephemeral=True)


bot.tree.add_command(whitelist)


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    if isinstance(error, app_commands.MissingPermissions):
        message = "Tu n'as pas la permission Discord nécessaire pour cette commande."
    else:
        log.error("Erreur de commande slash", exc_info=(type(error), error, error.__traceback__))
        message = "Une erreur est survenue. Vérifie les permissions du bot et réessaie."
    await send_private(interaction, message)


@bot.event
async def on_guild_join(guild: discord.Guild) -> None:
    get_config(guild.id)
    record_event(guild.id, 0, "SECURION", "bot ajouté", 1,
                 "SECURION a rejoint le serveur", "configuration initialisée")
    await send_log(guild, f"🛡️ SECURION est prêt sur {guild.name}. Lance /help pour voir les commandes.")


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.guild is None or message.author.bot or not isinstance(message.author, discord.Member):
        return
    cfg = get_config(message.guild.id)
    if not cfg["enabled"] or is_exempt(message.author, cfg):
        return
    now = time.monotonic()
    content = message.content or ""
    normalized_content = content.strip().casefold()
    fingerprint = (
        hashlib.sha256(normalized_content.encode("utf-8", "ignore")).hexdigest()
        if normalized_content else ""
    )
    detections: list[tuple[str, int, str]] = []

    if cfg["modules"].get("anti_spam", True):
        key = (message.guild.id, message.author.id)
        queue = message_windows.get(key)
        if queue is None:
            queue = deque(maxlen=80)
            message_windows[key] = queue
        message_windows.move_to_end(key)
        while len(message_windows) > 15000:
            message_windows.popitem(last=False)
        queue.append((now, fingerprint))
        seconds = cfg["thresholds"]["spam_seconds"]
        while queue and now - queue[0][0] > seconds:
            queue.popleft()
        if len(queue) >= cfg["thresholds"]["spam_count"]:
            repeats = sum(1 for _, value in queue if fingerprint and value == fingerprint)
            detections.append(("spam / flood", 7 if repeats >= 4 else 5,
                               f"{len(queue)} messages en {seconds} secondes, {repeats} répétition(s)"))
            queue.clear()

    if cfg["modules"].get("anti_mentions", True):
        mentions = len(message.mentions) + len(message.role_mentions)
        if message.mention_everyone or mentions >= cfg["thresholds"]["mention_count"]:
            detections.append(("mentions massives", 8 if message.mention_everyone else 7,
                               f"{mentions} mention(s), mention générale={message.mention_everyone}"))
    if cfg["modules"].get("anti_invites", True) and INVITE_RE.search(content):
        detections.append(("lien d'invitation Discord", 5, "Lien d'invitation détecté"))
    if not detections:
        return

    kind = " + ".join(name for name, _, _ in detections)
    severity = max(level for _, level, _ in detections)
    detail = " ; ".join(description for _, _, description in detections)
    action = "alerte et journalisation"
    if cfg["delete_triggering_message"] and not cfg["safe_mode"]:
        try:
            await message.delete()
            action = "message supprimé"
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            action = "alerte uniquement : suppression refusée"
    if cfg["auto_timeout"] and not cfg["safe_mode"] and severity >= 7:
        allowed, _ = await can_bot_moderate(message.guild, message.author)
        me = message.guild.me
        if allowed and me and me.guild_permissions.moderate_members:
            try:
                minutes = min(60, max(5, cfg["global_level"] * 5))
                await message.author.timeout(discord.utils.utcnow() + timedelta(minutes=minutes),
                                             reason=f"SECURION · {kind}"[:500])
                action += f" · timeout automatique {minutes} min"
            except (discord.Forbidden, discord.HTTPException):
                action += " · timeout automatique refusé"
    auto_warnable = any(name in {"spam / flood", "mentions massives"} for name, _, _ in detections)
    if cfg["auto_warning"] and not cfg["safe_mode"] and auto_warnable:
        warning_key = (message.guild.id, message.author.id)
        if now - auto_warning_at[warning_key] >= 60:
            auto_warning_at[warning_key] = now
            try:
                warning = await issue_warning(
                    message.author,
                    kind,
                    "SECURION (automatique)",
                    allow_escalation=True,
                )
                action += f" · avertissement automatique {warning['count']}/{warning['limit']}"
                if warning["sanction"]:
                    action += f" · {warning['sanction']['message']}"
            except Exception:
                # L'incident reste journalisé même si l'enregistrement d'avertissement échoue.
                log.exception("Échec de l'avertissement automatique pour %s dans %s",
                              message.author.id, message.guild.id)
                action += " · avertissement automatique impossible (voir les journaux Wispbyte)"
    record_event(message.guild.id, message.author.id, str(message.author), kind, severity, detail, action)
    await send_log(message.guild,
                   f"🚨 **{kind}** · {message.author.mention} ({message.author.id})\n"
                   f"Salon : {message.channel.mention}\nDétail : {detail}\nAction : {action}")


@bot.event
async def on_member_join(member: discord.Member) -> None:
    if member.bot:
        return
    cfg = get_config(member.guild.id)
    if not cfg["enabled"] or not cfg["modules"].get("anti_raid", True):
        return
    now = time.monotonic()
    queue = join_windows[member.guild.id]
    queue.append(now)
    seconds = cfg["thresholds"]["raid_seconds"]
    while queue and now - queue[0] > seconds:
        queue.popleft()
    created = member.created_at.strftime("%Y-%m-%d") if member.created_at else "inconnue"
    record_event(member.guild.id, member.id, str(member), "arrivée membre", 1,
                 f"Compte créé le {created}", "surveillance")
    if len(queue) >= cfg["thresholds"]["raid_joins"] and now - raid_alert_at[member.guild.id] >= seconds:
        raid_alert_at[member.guild.id] = now
        detail = f"{len(queue)} arrivées en {seconds} secondes. Vérification humaine recommandée."
        record_event(member.guild.id, member.id, str(member), "alerte anti-raid", 9, detail, "alerte uniquement")
        await send_log(member.guild,
                       f"⛔ **Alerte anti-raid**\n{detail}\nSECURION n'expulse pas de membres en masse.")


@bot.event
async def on_member_remove(member: discord.Member) -> None:
    record_event(member.guild.id, member.id, str(member), "départ ou retrait", 1,
                 "Membre parti ou retiré du serveur", "journalisation")


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User) -> None:
    record_event(guild.id, user.id, str(user), "bannissement observé", 5,
                 "Discord a signalé un bannissement", "journalisation")


@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User) -> None:
    with sqlite3.connect(DB_PATH, timeout=10) as con:
        con.execute(
            "UPDATE sanctions SET status='unbanned' WHERE guild_id=? AND user_id=? AND status='active'",
            (guild.id, user.id),
        )
    record_event(guild.id, user.id, str(user), "débannissement observé", 2,
                 "Discord a signalé un débannissement", "journalisation")


@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry) -> None:
    guild = entry.guild
    if guild is None:
        return
    cfg = get_config(guild.id)
    if not cfg["enabled"]:
        return
    action = getattr(entry.action, "name", str(entry.action)).casefold()
    actor_id = int(entry.user_id or 0)
    if bot.user and actor_id == bot.user.id:
        return
    actor = entry.user or (guild.get_member(actor_id) if actor_id else None)
    actor_name = str(actor) if actor else "Auteur inconnu"
    target = getattr(entry.target, "name", None) or str(getattr(entry.target, "id", "cible inconnue"))
    rules = {
        "webhook_create": ("anti_webhooks", "création de webhook", 8, "webhooks"),
        "webhook_update": ("anti_webhooks", "modification de webhook", 7, "webhooks"),
        "webhook_delete": ("anti_webhooks", "suppression de webhook", 8, "webhooks"),
        "channel_delete": ("anti_channels", "suppression de salon", 9, "salons"),
        "channel_create": ("anti_channels", "création de salon", 2, "salons"),
        "channel_update": ("anti_channels", "modification de salon", 4, "salons"),
        "overwrite_create": ("anti_channels", "création de permissions de salon", 5, "permissions"),
        "overwrite_update": ("anti_channels", "modification de permissions de salon", 6, "permissions"),
        "overwrite_delete": ("anti_channels", "suppression de permissions de salon", 5, "permissions"),
        "role_delete": ("anti_roles", "suppression de rôle", 9, "rôles"),
        "role_create": ("anti_roles", "création de rôle", 2, "rôles"),
        "role_update": ("anti_roles", "modification de rôle", 6, "rôles"),
        "member_role_update": ("anti_roles", "modification des rôles d'un membre", 5, "rôles"),
        "bot_add": ("anti_bots", "ajout d'un bot", 8, "bots"),
        "ban": ("anti_raid", "bannissement", 7, "sanctions"),
        "kick": ("anti_raid", "expulsion", 6, "sanctions"),
        "member_prune": ("anti_raid", "exclusion groupée de membres", 8, "sanctions"),
    }
    rule = rules.get(action)
    if not rule:
        return
    module, label, severity, burst_group = rule
    if not cfg["modules"].get(module, False):
        return
    detail = f"Action : {action} · cible : {target}"
    record_event(guild.id, actor_id, actor_name, label, severity, detail, "surveillance et journalisation")
    await send_log(guild, f"🔎 **{label}**\nActeur : {actor_name} ({actor_id or 'inconnu'})\n{detail}")
    if actor_id:
        key = (guild.id, actor_id, burst_group)
        queue = audit_windows[key]
        now = time.monotonic()
        queue.append(now)
        seconds = cfg["thresholds"]["destructive_seconds"]
        while queue and now - queue[0] > seconds:
            queue.popleft()
        if len(queue) >= cfg["thresholds"]["destructive_actions"] and now - audit_alert_at[key] >= seconds:
            audit_alert_at[key] = now
            alert = f"{len(queue)} actions {burst_group} en {seconds} secondes."
            record_event(guild.id, actor_id, actor_name, "alerte anti-nuke", 10, alert,
                         "alerte uniquement — aucune sanction automatique contre le staff")
            await send_log(guild, f"⛔ **Alerte anti-nuke** · {actor_name} ({actor_id})\n{alert}\nAucune sanction automatique n'a été déclenchée.")


def main() -> None:
    token = os.getenv("SECURION_TOKEN", "").strip()
    if not token:
        raise SystemExit("SECURION_TOKEN est absent. Ajoute le token dans les variables privées de l'hébergeur.")
    bot.run(token, log_handler=None)


if __name__ == "__main__":
    main()
