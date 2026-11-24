# SECURION — bot Discord avec commandes slash

Cette version se pilote avec les commandes slash de Discord. Le menu /panel s'ouvre dans Discord, en privé, et permet de définir le salon de logs par ID, gérer les avertissements et choisir les rôles/personnes autorisés.

## Commandes

- /help : guide interactif par catégorie.
- /panel : configuration, salon de logs, avertissements et accès.
- /configuration : raccourci vers /panel.
- /statut : état des protections.
- /diagnostic : vérifier l'anti-spam, le mode prudent et les permissions des salons.
- /protection pause et /protection reprendre : pause ou reprise.
- /protection prudent : activer ou désactiver le mode prudent.
- /protection timeout_auto : autoriser ou couper les timeouts automatiques.
- /protection niveau : sensibilité de 1 à 10.
- /protection module : activer ou désactiver un module.
- /sanction avertir, /sanction timeout, /sanction expulser, /sanction bannir, /sanction debannir : modération.
- /historique membre : derniers événements enregistrés pour un membre.
- /historique avertissements : qui a été averti, pourquoi et par qui.
- /historique actions : menus pour retirer un avertissement, réinitialiser le compteur, retirer un timeout et parcourir/débannir les personnes bannies.
- /wl ajouter, /wl retirer, /wl liste : liste blanche des membres et rôles.

Les commandes musique, tickets, salons vocaux et statistiques d'invitations des captures ne sont pas incluses : elles ne font pas partie des fonctions de sécurité de SECURION.

## Protections incluses

SECURION détecte le spam, les mentions massives, les liens d'invitation, les arrivées groupées et certains changements sensibles du serveur (salons, rôles, webhooks et ajout de bots). Il enregistre les événements dans SQLite et envoie les alertes, avertissements et sanctions dans le salon de logs défini dans /panel.

Par défaut, les avertissements automatiques sont actifs pour le spam et les mentions massives. Les liens d'invitation peuvent être supprimés, mais ne comptent pas comme avertissement automatique. Un même membre reçoit au plus un avertissement automatique par minute.

À 5 avertissements non consommés dans les 30 derniers jours, SECURION applique un ban temporaire de 2 jours, puis de 7 jours, puis de 30 jours pour les séries suivantes. Après ces 3 bans temporaires, la prochaine série de 5 avertissements entraîne un ban définitif. Les sanctions manuelles /sanction avertir suivent la même escalade.

Dans /historique actions, le menu Avertissements permet de retirer un avertissement actif précis ou de remettre à zéro tous les avertissements actifs d'une personne. Le menu Timeouts retire le timeout Discord d'un membre encore présent. Le menu Bannissements charge la liste réelle des bans du serveur, la parcourt par pages, puis débannit la personne sélectionnée. Les actions sont réservées aux personnes autorisées par Discord ou par /panel > Accès et sont inscrites dans le journal.

Le spam est détecté à partir de 5 messages en 5 secondes. Dans /panel > Accueil, le bouton « Réactiver l'anti-spam auto » remet les protections globales en marche, désactive le mode prudent, réactive l'anti-spam, les suppressions et les avertissements automatiques.

SECURION tente d'envoyer un message privé pour chaque avertissement et avant un bannissement, avec le motif et la durée. Si le membre a désactivé les messages privés ou si Discord les bloque, la sanction reste enregistrée dans l'historique et le salon de logs indique que le message n'a pas pu être envoyé.

Les timeout automatiques sont désactivés par défaut. Les alertes anti-raid et anti-nuke restent des alertes : SECURION ne bannit pas et n'expulse pas une foule de membres automatiquement. Le bouton Mode prudent de /panel arrête les suppressions et avertissements automatiques sans bloquer les sanctions manuelles du staff.

Pour tester l'anti-spam, utilise un compte membre ordinaire qui n'a pas de rôle staff, d'accès autorisé ou de liste blanche, puis envoie 5 messages en moins de 5 secondes. Les administrateurs, modérateurs et rôles/personnes autorisés sont volontairement ignorés par la détection automatique, mais les accès autorisés peuvent employer /sanction avertir et /sanction bannir manuellement. Lance /diagnostic pour vérifier les réglages et les permissions dans Discord.

Après une mise à jour, ouvre /panel > Accueil et clique sur « Réactiver l'anti-spam auto » pour remettre l'anti-spam, les suppressions et les avertissements automatiques en marche même si une ancienne configuration les avait désactivés.

Accès strict est activé par défaut : dans /panel, ajoute les rôles/personnes autorisés à lancer les commandes protégées. Tant que tu n'en as pas ajouté, seuls les administrateurs et responsables avec Gérer le serveur peuvent utiliser ces commandes. /panel reste réservé aux responsables du serveur. Si l'accès strict est désactivé, les permissions Discord habituelles sont aussi acceptées.

Les commandes protégées peuvent rester visibles dans le sélecteur de commandes Discord, mais SECURION refuse leur exécution aux personnes sans accès. La configuration d'accès par utilisateur/rôle est vérifiée côté bot.

## Démarrage sur Wispbyte

Choisis un serveur Python 3.10 ou supérieur.

1. Envoie main.py et requirements.txt dans le dossier du bot. N'envoie pas le dossier data, le fichier .env ou une base SQLite existante sur un dépôt public.
2. Configure la commande de démarrage : python main.py.
3. Ajoute la variable privée SECURION_TOKEN avec le token du bot. N'ajoute jamais le vrai token au code, à un dépôt public ou à une capture d'écran.
4. Installe les dépendances de requirements.txt si l'hébergeur ne les installe pas automatiquement.
5. Dans le Developer Portal Discord, active les intents privilégiés Server Members Intent et Message Content Intent. Le code active aussi l'intent de modération pour recevoir les événements du journal d'audit.
6. Invite le bot avec les scopes bot et applications.commands.
7. Accorde les permissions nécessaires : voir les salons, envoyer des messages, gérer les messages, modérer les membres, bannir et consulter le journal d'audit. Accorde aussi expulser si tu veux l'utiliser manuellement. Le rôle SECURION doit être au-dessus des membres à modérer. La liste des bans de /historique actions nécessite aussi la permission Bannir des membres.
8. Démarre le bot, puis utilise /help et /panel dans ton serveur.

Les intents Server Members et Message Content doivent être activés à la fois dans le code et dans le Developer Portal. Discord demande une revue d'accès aux intents privilégiés lorsque l'application est accessible à 10 000 utilisateurs ou plus ; la vérification de l'application est une démarche distincte. Sans l'intent Message Content actif, le bot ne peut pas lire le texte normal des messages pour détecter les liens et mentions. Vérifie les exigences actuelles dans le Developer Portal avant une publication à grande échelle.

SECURION ne peut lire que les salons où son rôle a la permission Voir le salon. Pour surveiller un fil privé, il faut aussi ajouter SECURION à ce fil. /diagnostic vérifie les salons textuels et les fils actifs connus du bot.

Pour tester les commandes dans un seul serveur avant leur publication générale, renseigne SECURION_TEST_GUILD_ID avec son identifiant. Retire cette variable pour synchroniser les commandes globalement.

## Fichiers de données

Les réglages sont enregistrés dans data/guilds/<ID_DU_SERVEUR>.json. L'historique, les avertissements et les bans temporaires sont enregistrés dans une base SQLite du dossier de données. Configure un dossier persistant dans Wispbyte si tu veux garder ces données après un redémarrage ou une réinstallation.

Si tu remplaces une ancienne version, garde le dossier de données. Quand data/events.sqlite3 existe, SECURION le réutilise et copie les anciens bans de la table moderation_bans dans son historique de sanctions, sans effacer l'ancienne table.

La mise à jour 4.3.0 ajoute un statut « retiré » aux avertissements ; la migration se fait au démarrage et conserve les anciennes entrées dans l'historique.

Le bot n'enregistre pas le contenu complet des messages. Il conserve les identifiants, dates, motifs et acteurs nécessaires à l'historique de sécurité.

Pour le stockage des secrets, des fichiers et des données, lis aussi security/SECURITY_FR.md.
