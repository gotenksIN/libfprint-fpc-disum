# FPC1022 driver rollback

## Ubuntu

```bash
sudo apt remove libfprint-fpc1022
sudo apt install libfprint-2-2 fprintd
sudo systemctl restart fprintd.service
```

## Arch Linux

```bash
sudo pacman -S libfprint
sudo systemctl restart fprintd.service
```

Do not enable fingerprint authentication in PAM unless both
`fprintd-enroll` and repeated `fprintd-verify` scans succeed. If PAM has
subsequently been configured, restore its backed-up files before removing a
working fingerprint setup.
