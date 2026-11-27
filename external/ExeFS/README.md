# ExeFS

Put the game's `main` NSO here as `external/ExeFS/main`. It is ignored by Git, so do not commit it.

Dump it from your own copy of *The Legend of Zelda: Breath of the Wild* (title `01007EF00011E000`).
Use the ExeFS of the v1.5.0 or v1.6.0 base game, or of the v1.9.0 update NSP, for example with
`hactool` and your console's `prod.keys`.

`setup` accepts compressed or uncompressed v1.5.0, v1.6.0 and v1.9.0 files, identified by SHA-256.
Versions other than 1.5.0 are downgraded with the decomp's published xdelta3 patch. To use a file
stored elsewhere, pass `setup --nso PATH` or set `BOTW_NSO`.
