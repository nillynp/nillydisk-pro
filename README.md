# NillyDisk Pro — Ultra-Light Native Disk Space Analyzer, Treemap, SHA-256 Duplicate Finder & Safe Cleaner

> **Πανάλαφρος native Win32 Αναλυτής Δίσκου, Διαδραστικό Treemap, Εύρεση Ακριβών Διπλοτύπων (SHA-256) & Ασφαλής Cache Cleaner για Windows 10/11!**
> **Σάρωση μόνο για ανάγνωση · Μεταφορά επιλεγμένων αρχείων στον Κάδο μέσω Windows · Επιλεκτικός καθαρισμός cache**
>
> **created by [Nilly graphics (Nillygraphics · Sotiris Christos)](https://nillygraphics.com/)**

> **Διαγραφή στη v1.0.** Η σάρωση είναι μόνο για ανάγνωση. Ο καθαρισμός cache διαγράφει απευθείας τα επιλεγμένα προσωρινά αρχεία. Το προαιρετικό άδειασμα του Κάδου είναι οριστικό.

[Σελίδα εργαλείου](https://nillygraphics.com/product/nillydisk-pro/el/) · [Λήψη v1.0](https://github.com/nillynp/nillydisk-pro/releases/tag/v1.0)

---

## Σύγκριση

| Εργαλείο | Μέγεθος | Διαδραστικό Treemap | SHA-256 Διπλότυπα | Ασφαλής Cache Cleaner | Zero-Admin Portable | Τιμή |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| TreeSize / CCleaner | — | TreeSize | TreeSize Professional | CCleaner | Ανά έκδοση | Free και Professional |
| Windows Storage Sense | Ενσωματωμένο | Όχι | Όχι | Βασικό | Όχι | — |
| **NillyDisk Pro** | **~79 KB EXE (εκτίμηση δημιουργού)** | **Ναι (Color-Coded)** | **Ναι (3-Stage SHA-256)** | **Ναι, με επιλογή κατηγοριών** | **Ναι (0 DLLs)** | **0€ (MIT)** |

---

## Δυνατότητες & 4 Δικλείδες Ασφαλείας

1. **⚡ Win32 `FindFirstFileEx` Ανάλυση & Διαδραστικό Treemap:**
   - Σαρώνει δίσκους (`C:`, `D:`) ή μεμονωμένους φακέλους με `FIND_FIRST_EX_LARGE_FETCH`, παραλείποντας ασφαλώς Junctions/Symlinks (0 loops).
   - **Αριστερά:** Drill-down λίστα φακέλων με ζωντανές οριζόντιες μπάρες ποσοστού (`%`), μέγεθος, πλήθος αρχείων & Export σε **CSV**.
   - **Δεξιά:** Διαδραστικό **Squarified Treemap** με χρωματική κατηγοριοποίηση για δημιουργικά studio (**Design/3D `.psd/.ai/.cdr/.max/.c4d`** Πορτοκαλί, **Εικόνες** Γαλάζιο, **Video/Audio** Ροζ, **PDF/Docs** Πράσινο, **Archives** Μωβ).
2. **🏆 Top 300 Μεγαλύτερα Αρχεία & Κατανομή ανά Τύπο (Extensions):**
   - Βλέπεις αμέσως ποια αρχεία και ποιες επεκτάσεις (`.psd`, `.mp4`, `.max`, `.pdf`, `.zip`) τρώνε τον δίσκο, με ζωντανό φίλτρο αναζήτησης.
3. **🧬 Εύρεση Διπλοτύπων (3-Stage SHA-256):**
   - Ομαδοποίηση μεγέθους → γρήγορο αποτύπωμα 64 KB Head+Tail → πλήρες **SHA-256** για τελική ομαδοποίηση βάσει hash..
   - **Αυτόματη Επιλογή Παλαιότερων** (κρατάει το νεότερο πρωτότυπο) + σκληρό κλείδωμα ώστε να **μην διαγράφονται ποτέ όλα τα αντίγραφα** μιας ομάδας!
4. **🧹 Επιλεκτικός Καθαρισμός Cache:**
   - Εμφανίζει την εκτιμώμενη χρήση χώρου και καθαρίζει τις επιλεγμένες κατηγορίες: Windows User Temp, Adobe Media Cache & Camera Raw Cache, NVIDIA/DirectX Shaders, Crash Dumps, Disk Cache browsers (Chrome/Edge/Firefox — **0 κωδικοί, 0 cookies, 0 tabs!**) και προαιρετικά Κάδο Ανακύκλωσης.
   - **Προστασία Συστήματος:** Αποκλείει διαγραφές σε `C:\Windows`, `Program Files`, `ProgramData` και άλλες προστατευμένες διαδρομές. Για επιλεγμένα αρχεία και διπλότυπα η εφαρμογή ζητά από τα Windows μεταφορά στον Κάδο.

---

## Εγκατάσταση σε Windows 10/11 (Portable · Χωρίς Admin)

1. Κατέβασε το **`NillyDisk-Pro-v1.0-Portable.zip`** και αποσυμπίεσέ το όπου θες (π.χ. `C:\Tools\NillyDiskPro`).
2. Τρέξε με διπλό κλικ το **`Install_NillyDiskPro.bat`** *(δεν απαιτεί δικαιώματα Administrator!)*.
   - Το ZIP περιέχει πηγαίο κώδικα και installer. Μεταγλωττίζει αυτόματα το 100% native **`NillyDiskPro.exe`** με τον ενσωματωμένο `.NET` compiler των Windows (0 εξωτερικά DLLs / 0 downloads).
   - Προσθέτει **`Ανάλυση Χώρου με NillyDisk Pro`** στο δεξί κλικ δίσκων/φακέλων και συντομεύσεις σε Desktop & Start Menu.

### Απεγκατάσταση
Τρέξε το **`Uninstall_NillyDiskPro.bat`** — αφαιρεί καθαρά όλες τις συντομεύσεις & το δεξί κλικ χωρίς να αγγίξει κανένα αρχείο σου.

---

## Οικοσύστημα Δωρεάν Εργαλείων Windows — created by Nilly graphics (Nillygraphics · Sotiris Christos)

Όλα τα εργαλεία είναι **100% Δωρεάν (0€, MIT Open-Source)**, native Windows 10/11, Zero-Admin Portable και σχεδιασμένα από **[Nilly graphics (Sotiris Christos)](https://nillygraphics.com/)**:

| Εργαλείο | Τι αντικαθιστά | Μέγεθος | Σύνδεσμος |
| :--- | :--- | :---: | :--- |
| **NillyDisk Pro** | TreeSize / WinDirStat / Duplicate Finder / Cache Cleaner | ~79 KB | [GitHub](https://github.com/nillynp/nillydisk-pro) |
| **NillyCode Pro** | Sublime Text (58 MB) | ~104 KB | [GitHub](https://github.com/nillynp/nillycode-pro) |
| **NillyCalc Pro** | Windows Calculator (18 MB) | ~72 KB | [GitHub](https://github.com/nillynp/nillycalc-pro) |
| **NillyBatch Pro** | Adobe Bridge (1.95 GB) | ~66 KB | [GitHub](https://github.com/nillynp/nillybatch-pro) |
| **NillyMedia Lite** | Windows Media Player & Voice Recorder (46 MB) | ~52 KB | [GitHub](https://github.com/nillynp/nillymedia-lite) |
| **NillyView Pro** | Windows Photos & Paint | ~45 KB | [GitHub](https://github.com/nillynp/nillyview-pro) |
| **NillyDoc Pro** | Heavy PDF Viewers / Editors | ~2 MB | [GitHub](https://github.com/nillynp/nillydoc-pro) |
| **Nilly PC Manager & Tools** | All-in-One Studio & PC Maintenance Suite | Portable | [GitHub](https://github.com/nillynp/nilly-pc-manager-tools) |

---

## Author, Credits & SEO

- **Created by:** **[Nilly graphics (Nillygraphics · Sotiris Christos)](https://nillygraphics.com/)**
- **Website:** [https://nillygraphics.com/](https://nillygraphics.com/)
- **GitHub:** [https://github.com/nillynp](https://github.com/nillynp)
- **License:** MIT License — 100% Free & Open Source (0€)

> **English Summary:** **NillyDisk Pro** is a free, ultra-lightweight (~79 KB executable, developer estimate), open-source native Windows 10/11 disk space analyzer with an interactive color-coded treemap, top largest files & extension breakdown, 3-stage cryptographic SHA-256 duplicate finder, and selective cache cleanup. Scanning is read-only. For selected files and duplicates, the app asks Windows to use the Recycle Bin. The cleaner deletes selected temporary files directly, and emptying the Recycle Bin is permanent. **Created by Nilly graphics (Nillygraphics · Sotiris Christos)** ([nillygraphics.com](https://nillygraphics.com/)).
> **Keywords:** `NillyDisk Pro`, `Nilly graphics`, `Nillygraphics`, `Sotiris Christos`, `nillygraphics.com`, `free TreeSize WinDirStat alternative`, `Windows 11 disk space analyzer`, `treemap storage analyzer`, `SHA-256 duplicate file finder`, `safe Adobe Media Cache cleaner`, `portable disk cleaner`
