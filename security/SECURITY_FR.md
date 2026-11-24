# Sécuriser SECURION sur Wispbyte

## Le token du bot

- Renseigne le token Discord uniquement dans la variable privée SECURION_TOKEN de Wispbyte.
- Ne colle jamais le token dans main.py, dans .env.example, dans une commande de démarrage, dans un message ou dans une capture.
- Ne téléverse pas un vrai fichier .env dans un dépôt public.
- Si le token a été publié ou envoyé à quelqu'un, régénère-le dans le Developer Portal Discord et remplace immédiatement la variable Wispbyte.
- Active l'authentification à deux facteurs sur le compte Discord et le compte Wispbyte.

## Les fichiers de données

- Le dossier data contient les configurations, IDs, motifs de modération, avertissements et bans temporaires. Ne le partage pas publiquement.
- Le programme demande des permissions privées au système pour data (0700), les fichiers de configuration (0600) et la base SQLite. Le système peut ignorer ces permissions sur certains environnements.
- Le fichier .gitignore exclut les secrets, les bases de données et les journaux des commits accidentels. Il ne protège pas les fichiers déjà téléversés chez l'hébergeur.
- Choisis un répertoire de données persistant et privé dans SECURION_DATA_DIR si Wispbyte en fournit un.

## Permissions et accès Discord

- Dans /panel, ajoute uniquement les rôles et personnes de confiance.
- Accès strict est activé par défaut. Ajoute uniquement les rôles/personnes de confiance dans /panel. Les administrateurs et responsables avec Gérer le serveur gardent l'accès pour éviter de verrouiller le propriétaire dehors.
- Garde SECURION avec les permissions nécessaires seulement. N'accorde pas Administrateur si le bot n'en a pas besoin.
- Place le rôle du bot juste au-dessus des rôles qu'il doit modérer.
- Garde une sauvegarde privée des données si tu veux conserver l'historique; supprime-la lorsque tu n'en as plus besoin.

## Limite importante

Aucun dossier créé dans le bot ne peut empêcher l'exploitant de l'hébergeur ou une personne ayant accès au compte Wispbyte d'inspecter ses fichiers et ses variables. Ces mesures réduisent les fuites accidentelles et les accès non autorisés dans Discord; elles ne peuvent pas rendre les fichiers impossibles à voler.
