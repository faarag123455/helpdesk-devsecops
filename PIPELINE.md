# Pipeline CI/CD – HelpDesk (GitLab CI)

Responsable : Farah Chebbi · Module DevSecOps, ING-5-SSIRF-B

## 1. Vue d'ensemble

```
test ─┐
sast ─┤
secrets ─┼──► build ──► image-scan
dependencies ─┘
```

Les quatre contrôles du haut démarrent **en parallèle**. L'image Docker n'est construite
et poussée dans le registre que si **tous** sont verts (`needs`). Chaque scanner affiche
ainsi son propre résultat, même si un autre échoue.

Image produite (nom unique, utilisé aussi par les manifestes Kubernetes) :

```
$CI_REGISTRY_IMAGE/helpdesk-app:$CI_COMMIT_SHA
```

## 2. Politique de blocage

| Étape | Outil | Le pipeline échoue si… | Justification |
|---|---|---|---|
| test | py_compile | le code Python ne compile pas | contrôle de base |
| sast | Semgrep (`p/python`, `p/flask`) | une trouvaille de gravité ERROR existe dans `app/` | motifs dangereux (injection, désérialisation…) |
| secrets | Gitleaks | **tout** secret est détecté, dans les fichiers ou l'historique Git | un secret exposé se révoque, il ne se tolère pas |
| dependencies | Trivy `fs` | une vulnérabilité CRITICAL ou HIGH **avec correctif disponible** existe | si un correctif existe, le risque n'est pas justifiable |
| build | Docker | la construction ou le push échoue | |
| image-scan | Trivy `image` | même politique que `dependencies`, sur l'image finale | couvre aussi les paquets système |

Les valeurs des secrets ne sont **jamais** affichées (`--redact`) : seuls la règle,
le fichier et la ligne apparaissent.

## 3. Détection des secrets : règle personnalisée

Les règles par défaut de Gitleaks reconnaissent des formats précis (AWS, GitHub…) ou des
chaînes très aléatoires. Elles **ne détectent pas** `SECRET_KEY = "fake-secret-key-123"`
(testé). Le fichier `.gitleaks.toml` conserve toutes les règles par défaut et ajoute la règle
`helpdesk-hardcoded-credential` : un identifiant de type `secret_key`, `api_token`, `password`,
`token`… affecté à une valeur littérale d'au moins 8 caractères.

Les références (`os.environ[...]`, `${VAR}`, `$CI_VARIABLE`, `secretKeyRef`) sont ignorées,
afin que le code corrigé ne produise pas de faux positifs.

Sur l'application initiale, cette règle détecte 6 secrets fictifs : 3 dans `config.py`
(VULN-5) et 3 dans `docker-compose.yml`.

## 4. Rotation d'un secret exposé : l'ordre des opérations

1. **Révoquer ou remplacer d'abord** le secret (nouveau mot de passe / nouveau jeton).
   Tant que l'ancien fonctionne, il reste exploitable, même supprimé du code.
2. **Corriger le code** : lire la valeur depuis une variable d'environnement
   (variables protégées GitLab, Secret Kubernetes).
3. **Nettoyer ensuite** :
   - option A : réécrire l'historique (`git filter-repo`) puis forcer le push ;
   - option B : le secret étant déjà révoqué, enregistrer l'existant comme *baseline* :

     ```bash
     gitleaks detect --source . --config .gitleaks.toml --redact \
       --report-format json --report-path .gitleaks-baseline.json
     ```

     Le pipeline lit automatiquement `.gitleaks-baseline.json` : les anciennes trouvailles
     sont ignorées, tout **nouveau** secret fait échouer le pipeline.
4. **Vérifier** : le job `secrets` repasse au vert.

## 5. Preuves à fournir

- [ ] Capture : pipeline en échec à l'étape `secrets` (secrets détectés, valeurs masquées)
- [ ] Capture : pipeline en échec à l'étape `dependencies` (Flask / Werkzeug 2.2.2, VULN-7)
- [ ] Capture : pipeline en échec à l'étape `sast` (Semgrep)
- [ ] Capture : pipeline entièrement vert après correction (comparaison avant/après)
- [ ] Merge request ouverte puis fusionnée dans `main`

### Preuve « secret fictif » sur une branche jetable

```bash
git checkout farah/pipeline
git checkout -b farah/test-secret
echo 'AWS_SECRET_ACCESS_KEY = "AKIAFAKEEXAMPLE1234567890"' > leak_test.txt
git add leak_test.txt
git commit -m "test: fake secret (branche jetable, ne pas fusionner)"
git push -u origin farah/test-secret
```

Lancer le pipeline sur cette branche, capturer le journal du job `secrets` où apparaît
`leak_test.txt`, puis supprimer la branche :

```bash
git checkout farah/pipeline
git push origin --delete farah/test-secret
git branch -D farah/test-secret
```

> Le secret reste visible dans l'historique de cette branche tant qu'elle existe : c'est
> pourquoi elle ne doit jamais être fusionnée.
