# Ресурсы Windows

Иконки, манифест (права администратора, DPI) и сведения о версии для `VPN-TLS.exe`
лежат в `cmd/vpntls-windows/rsrc_windows_*.syso` — Go встраивает их при сборке сам.

Пересоздать после изменения иконок (`assets/icon/draw.py`):

```bash
cd assets/icon && python3 draw.py
cd ../../tools/winres && go run . -version 0.2.0
```
