<!-- Généré par `bun run gen:keys` depuis app/src/help/table.ts. Ne pas éditer. -->

# Raccourcis

## Profils

Liste des profils VPN importés avec leur état. Point d'entrée du TUI.

| Touche | Action |
| --- | --- |
| `↑ ↓ j k` | naviguer |
| `Entrée` | up/down |
| `d` | détail |
| `s` | accepter le scope appris |
| `i` | importer |
| `n` | nouveau |
| `e` | éditer |
| `x` | supprimer |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Naviguer, monter ou couper le tunnel.
- Importer, créer, éditer ou supprimer un profil.

> Attention : Supprimer un profil demande une confirmation.
> Attention : Monter un profil arme le kill switch.

## Détail

Détail d'un profil : routes, DNS, scope appris et état de la connexion.

| Touche | Action |
| --- | --- |
| `s` | accepter le scope |
| `e` | éditer |
| `Esc` | retour |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Accepter le scope appris pour l'ajouter aux routes autorisées.
- Éditer le profil.

> Attention : Accepter un scope élargit ce que le tunnel peut atteindre : vérifier avant de valider.

## Logs

Journal des événements du daemon : connexions, reconnexions, kill switch.

| Touche | Action |
| --- | --- |
| `↑ ↓ j k` | naviguer |
| `PgUp PgDn` | page |
| `Esc` | retour |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Parcourir les événements récents.

## Import

Import d'un fichier de profil (.ovpn ou WireGuard) en trois temps : chemin, aperçu, confirmation. Les secrets vont dans le trousseau, pas sur disque.

| Touche | Action |
| --- | --- |
| `Entrée` | lire / importer |
| `tab` | compléter / suivant |
| `shift+tab` | champ précédent |
| `Esc` | annuler |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Saisir le chemin (~ accepté, Tab complète le nom), puis Entrée pour lire le fichier et afficher l'aperçu.
- Ajuster le nom et l'identifiant, puis Entrée sur « Importer ».

> Attention : Un fichier refusé affiche le message exact du parseur ou du daemon, ligne par ligne, et rien n'est importé.
> Attention : Les secrets ne sont jamais affichés.

## Édition / création

Formulaire de création d'un profil OpenVPN ou WireGuard (n), ou d'édition du profil sélectionné (e) : nom, tags, couleur, scope, kill switch, DNS. Le type et la configuration ne sont pas modifiables : réimporter le fichier.

| Touche | Action |
| --- | --- |
| `tab` | champ suivant |
| `shift+tab` | champ précédent |
| `Entrée` | valider le champ / bouton |
| `ctrl+s` | enregistrer |
| `Esc` | annuler |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Passer d'un champ à l'autre, Entrée sur le bouton pour enregistrer.
- Les secrets (clé privée, mot de passe, blocs PEM sensibles) sont masqués et passent par le trousseau.

> Attention : Annuler un formulaire modifié demande une confirmation.
> Attention : Désactiver le kill switch laisse le scope non protégé.
> Attention : Les lettres tapées dans un champ de saisie ne déclenchent aucun raccourci.

## Aide

Rappel des touches de la vue courante et du fonctionnement du kill switch.

| Touche | Action |
| --- | --- |
| `↑ ↓ j k` | défiler |
| `PgUp PgDn` | page |
| `Esc` | fermer |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Lire, puis fermer.

## Confirmation

Fenêtre de confirmation avant une action destructrice (suppression, scope). Le panic-off exige de taper « oui ».

| Touche | Action |
| --- | --- |
| `o` | oui |
| `n Esc` | non |
| `?` | aide (global) |
| `q` | quitter (global) |
| `!` | panic-off (global) |
| `L` | logs (global) |
| `y` | copier LHOST (global) |

- Répondre oui ou non.

> Attention : « y » reste réservé à la copie du LHOST : la confirmation utilise « o ».

## Kill switch

Le daemon pose une table nftables `inet vpn_tui` qui coupe tout trafic hors tunnel.

- **DÉSARMÉ** : Aucun tunnel, aucune règle. Rien n'est bloqué.
- **ARMÉ** : Tunnel établi. Tout trafic hors du tunnel est bloqué ; seuls le tunnel et le lien local passent.
- **VERROUILLÉ** : Tunnel perdu ou reconnexions épuisées. Tout le trafic reste bloqué, y compris hors tunnel, jusqu'à une action manuelle (up ou panic-off).
- **RECONNEXION** : Tunnel perdu, nouvelle tentative en cours. Le trafic hors tunnel reste bloqué pendant les tentatives.

panic-off supprime les règles du kill switch et rend l'accès réseau normal, avec confirmation obligatoire. Sans daemon, exécuter en root `vpn-tuid --panic-off` ou `nft delete table inet vpn_tui`.
