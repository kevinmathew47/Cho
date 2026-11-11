# Practice challenges

## practice-evidence.zip — "Hidden in Plain Sight"

- **Category**: digital forensics / steganography (easy)
- **Prompt**: Find the flag hidden in the supplied image.
- **Flag format**: `flag{...}`
- **Intended approach**: inspect the PNG metadata; a text chunk holds a Base64 string that decodes to the flag.
- **Flag**: `flag{pl41n_s1ght_m3t4d4t4}`
- **Origin**: generated for this project; the image is synthetic.

More categories (cryptography, reverse engineering, web) are on the roadmap in `docs/ARCHITECTURE.md`.
