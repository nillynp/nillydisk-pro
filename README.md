# NillyDisk Pro

Δωρεάν αναλυτής χώρου δίσκου για Windows 10/11 με διαδραστικό treemap, εντοπισμό διπλοτύπων SHA-256 και καθαρισμό προσωρινών αρχείων. **0 € · Άδεια MIT**. Δημιουργία [Nilly graphics (Nillygraphics · Sotiris Christos)](https://nillygraphics.com/).

[Λήψη v1.0](https://github.com/nillynp/nillydisk-pro/releases/tag/v1.0) · [Σελίδα εργαλείου](https://nillygraphics.com/product/nillydisk-pro/el/)

## Δυνατότητες

- Σάρωση Win32 μόνο για ανάγνωση, με χρωματικό treemap, drill-down και εξαγωγή CSV.
- Τα 300 μεγαλύτερα αρχεία και κατανομή ανά επέκταση, όπως PSD, AI, MP4, MAX και PDF.
- Ομαδοποίηση με βάση το μέγεθος, μερικό hash και πλήρες SHA-256. Κατά την ομαδική διαγραφή η εφαρμογή εξαιρεί τουλάχιστον ένα αρχείο ανά ομάδα.
- Προεπισκόπηση και επιλογή καθαρισμού για Windows Temp, Adobe Media/Camera Raw Cache, NVIDIA/DirectX shaders, crash dumps και disk cache των Chrome, Edge και Firefox.

**Διαγραφή αρχείων στη v1.0.** Η σάρωση από μόνη της είναι μόνο για ανάγνωση. Για τα επιλεγμένα αρχεία και διπλότυπα η εφαρμογή ζητά μεταφορά στον Κάδο Ανακύκλωσης μέσω Windows. Ο καθαρισμός cache διαγράφει τα επιλεγμένα προσωρινά αρχεία απευθείας. Αν ενεργοποιήσεις την ξεχωριστή επιλογή αδειάσματος του Κάδου, τα περιεχόμενά του αφαιρούνται οριστικά.

## Εγκατάσταση χωρίς διαχειριστή

1. Κατέβασε και αποσυμπίεσε το `NillyDisk-Pro-v1.0-Portable.zip`.
2. Εκτέλεσε το `Install_NillyDiskPro.bat`. Το ZIP περιέχει πηγαίο κώδικα και installer. Ο installer δημιουργεί το `NillyDiskPro.exe` με τον compiler του .NET Framework 4.x των Windows και προσθέτει συντομεύσεις και μενού Explorer για τον τρέχοντα χρήστη.
3. Άνοιξε το EXE ή τη συντόμευση και διάλεξε δίσκο ή φάκελο. Το `Uninstall_NillyDiskPro.bat` αφαιρεί τις καταχωρίσεις του χρήστη.

## English

NillyDisk Pro is a free, open-source disk space analyzer for Windows 10 and 11. Inspect disk usage with an interactive treemap, see the 300 largest files, review space by extension, and find duplicates using a three-stage SHA-256 workflow. The cache cleaner can target Windows temporary files, Adobe media cache, GPU shader caches, and browser disk caches.

Scanning is read-only. Selected files and duplicates are sent to Windows with a request to use the Recycle Bin. Cache cleaning deletes the chosen temporary files directly. Emptying the Recycle Bin is a separate action and permanently removes its contents.

Download and extract the [v1.0 release](https://github.com/nillynp/nillydisk-pro/releases/tag/v1.0), then run `Install_NillyDiskPro.bat` as a regular user. The installer compiles the executable locally using the Windows .NET Framework 4.x compiler. See [Nilly graphics](https://nillygraphics.com/product/nillydisk-pro/en/) for the product page.

## License

[MIT](LICENSE) · [Nilly graphics (Nillygraphics · Sotiris Christos)](https://nillygraphics.com/)
