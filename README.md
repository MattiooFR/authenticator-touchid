# Authenticator Touch ID

Extension Chrome de codes 2FA (TOTP/HOTP, Steam, Battle.net) pour macOS.
Coffre chiffré, ouvert par **Touch ID** ou par mot de passe, et filtré automatiquement selon le site ouvert.
Alternative à l'extension [Authenticator](https://authenticator.cc), dont elle importe les sauvegardes.

## Installer

Il faut un Mac avec Touch ID, Chrome 132 ou plus, et les outils de développement Apple
(`xcode-select --install`) pour compiler la petite app Touch ID.

```sh
git clone https://github.com/MattiooFR/authenticator-touchid.git
cd authenticator-touchid
./native/install.sh
```

1. `chrome://extensions` → activer « Mode développeur » → « Charger l'extension non empaquetée » → dossier `src/`.
2. Épingler l'icône. Raccourci : `⌥⇧A`.
3. Créer le mot de passe, puis Réglages → **Activer Touch ID** → poser le doigt.
4. Importer les comptes.

### Ce que fait `native/install.sh`

- compile `native/main.swift` (≈ 120 lignes) dans `~/Library/Application Support/AuthenticatorTouchID/` ;
- le signe localement (signature ad hoc, pas besoin de compte développeur Apple) ;
- écrit le manifeste d'hôte natif `com.authenticator.touchid.json` dans le dossier `NativeMessagingHosts`
  de Chrome (et de Brave, Edge, Chromium s'ils sont installés). Seule cette extension a le droit de lui parler.

Pas de `sudo`. Pour désinstaller : supprimer ce dossier et ces fichiers `com.authenticator.touchid.json`.

L'ID de l'extension (`pmbilcebaiegkjgcjhobcmkcaiafddon`) est fixé par la clé publique `key` du manifest :
il reste le même quel que soit le dossier, et c'est lui que l'hôte natif autorise.
Si tu modifies ou retires `key`, mets le nouvel ID dans `native/install.sh` et relance-le.

### Comment marche Touch ID

- L'extension envoie un message à l'app par la messagerie native de Chrome.
- L'app crée une clé dans la **Secure Enclave** du Mac, utilisable seulement après Touch ID.
- Elle en tire un secret de 32 octets qui déchiffre le coffre, et ne le donne qu'après l'empreinte.

Pourquoi une app d'aide : Chrome n'offre aucune API Touch ID aux extensions. Bitwarden et 1Password
passent aussi par la messagerie native. Les passkeys (WebAuthn PRF) ont été essayés : depuis une page
`chrome-extension://`, le choix « Trousseau iCloud » fige Chrome.

## Sécurité

- Les comptes sont chiffrés en AES-256-GCM par une clé de données (DEK) aléatoire.
- La DEK est emballée deux fois : par une clé PBKDF2-SHA256 (600 000 itérations) du mot de passe,
  et par un secret de 32 octets calculé par la **Secure Enclave** : une clé P-256 créée dans la puce,
  utilisable seulement après Touch ID (empreintes actuelles), fait un échange ECDH puis HKDF.
  Touch ID déchiffre donc vraiment le coffre ; ce n'est pas un simple contrôle de présence.
  La clé ne quitte jamais la puce : sur un autre Mac, on restaure avec le mot de passe.
- Une fois ouvert, la DEK vit dans `chrome.storage.session` (mémoire seule, illisible par les pages web),
  effacée au verrouillage, après l'inactivité réglée, au verrouillage de l'écran du Mac, ou à la fermeture de Chrome.
- Verrouillage automatique réglable : dès la fermeture de la fenêtre, 1 min à 4 h, ou à la fermeture de Chrome.
- Le mot de passe doit atteindre le niveau « Bon » : au moins 1 000 ans pour le craquer avec 100 cartes graphiques
  qui attaquent une sauvegarde volée (estimation dans `src/lib/strength.js`).
- CSP stricte, permissions minimales : `storage`, `activeTab`, `alarms`, `idle`, `clipboardWrite`, `scripting`,
  `nativeMessaging`. Aucun accès aux pages tant que tu n'as pas ouvert l'extension dessus.
- Une seule bibliothèque, copiée dans `src/vendor/` : [@noble/hashes](https://github.com/paulmillr/noble-hashes)
  (Argon2id et MD5, seulement pour lire les exports chiffrés d'Authenticator). `npm run vendor` la recopie.

## Filtrage par site

- Copier un code sur un site associe ce site au compte (domaine racine : `app.supabase.com` → `supabase.com`).
- À l'ouverture sur ce site, seuls les comptes associés s'affichent, triés par usage. « Tous les comptes » montre le reste.
- Sans association, un compte dont le nom ressemble au domaine est proposé avec le badge « suggéré ».
- Les sites associés se modifient dans « … » sur la carte.
- Scanner le QR code d'une page de configuration 2FA associe directement le compte à ce site.

## Remplissage automatique

Cliquer sur un code (ou Entrée) le copie et le tape dans la page, seulement si un champ ressemble
vraiment à un champ 2FA (`autocomplete="one-time-code"`, nom otp/code/2fa, ou 6 cases séparées).
Une page de connexion classique (e-mail, mot de passe, recherche) n'est jamais remplie. Désactivable dans les réglages.

## Sauvegardes automatiques

Le coffre stocké est déjà chiffré : le service worker le sauvegarde à chaque changement, sans le déverrouiller.

- **Compte Google** (`chrome.storage.sync`) : un emplacement par appareil, donc aucun appareil n'écrase l'autre.
  Il faut la synchro Chrome activée pour les extensions. Sur un nouveau Mac, l'écran de création propose de restaurer.
- **Dossier** (iCloud Drive…) : `authenticator-latest.json` + une copie par jour, 30 jours gardés.
  Chrome redemande parfois l'accès : un bandeau « Reconnecter le dossier » apparaît.
- Un `!` rouge sur l'icône signale une sauvegarde en échec.

## Importer depuis l'extension Authenticator (authenticator.cc)

Engrenage → Sauvegarde → télécharger le fichier, puis Réglages → Importer.

- Fichier `.json` **avec ou sans mot de passe** : un champ mot de passe apparaît si l'export est chiffré.
  Les trois formats de chiffrement d'Authenticator sont lus (Argon2id actuel, et les deux anciens).
- Fichier `.txt` (liens `otpauth://`).
- Comptes Steam et Battle.net compris.

Sont aussi acceptés : des liens `otpauth://` et les exports Google Authenticator (`otpauth-migration://`).

## Tests

`npm test` (vecteurs officiels RFC 4226 / 6238, imports, chiffrement).

## Licence

MIT.
