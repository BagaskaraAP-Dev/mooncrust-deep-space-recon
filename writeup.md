# Writeup — Mooncrust: Deep Space Recon

| | |
|---|---|
| **Challenge** | Mooncrust: Deep Space Recon |
| **Kategori** | Reverse Engineering / Cryptography (Web-based) |
| **Target** | `https://adventuremnc.mooncrust.my.id` |
| **Cipher** | MNC-SPN-16 (custom 4-round SPN, 128-bit) |
| **Format Flag** | `KTCG{...}` |
| **Flag** | `KTCG{M00nc2ust_l3v3l_b494sB3Rc4nd4_BagaskaraAP-Dev}` |

---

## Deskripsi

> Selamat datang di Sektor 04 Kutub Selatan Bulan! Sambil menjelajahi kawah dan mengendarai *mining rover*, kamu mendeteksi sinyal *downlink* rahasia dari satelit **MNC-SAT-4**.
>
> Sayangnya, transmisi data telemetrinya terkunci oleh koprocessor kriptografi kustom **MNC-SPN-16**. Bisakah kamu membongkar sistemnya dan mengekstrak flag yang terenkripsi?
>
> 🔗 **Target:** `https://adventuremnc.mooncrust.my.id`
> 🚩 **Format Flag:** `KTCG{...}`

Petunjuk in-game:
- Target adalah **web game 3D**; inti soal ada di **bundle JS**, bukan di grafiknya.
- Buka DevTools Console → ada objek `window.MNC` dengan `MNC.scan()`, `MNC.dump()`, `MNC.execute(key)`. Tombol `[T]` in-game membuka terminal telemetry.
- Verifikasi butuh **16-byte key** yang lolos algoritma `MNC-SPN-16`, lalu key itu dipakai mendekripsi payload.

---

## 1. Reconnaissance

Halaman utama cuma memuat satu module JS:

```html
<script type="module" crossorigin src="/assets/index-BmWmjY1L.js"></script>
```

Tarik bundle-nya dan cari simbol crypto (`MNC`, `SPN`, `diffuse`, S-box):

```bash
curl -s https://adventuremnc.mooncrust.my.id/ -o index.html
curl -s https://adventuremnc.mooncrust.my.id/assets/index-BmWmjY1L.js -o bundle.js
grep -nio 'MNC\|SPN\|diffuse\|dump\|CIPHERTEXT' bundle.js
```

Seluruh logika ada di satu class ter-minify, `class ui`. Bagian pentingnya (sudah dirapikan):

```js
const Gc = new Uint8Array([99,124,119,123,242, ...]);   // AES S-box standar
const Hc = [ /* 4 round key, masing-masing 16 byte */ ];  // KONSTAN
const Wc = new Uint8Array([48,54,62,52,225,2,236,229,15,191,201,127,29,112,167,122]); // target signature
const ss = new Uint8Array([249,166,40,12, ...]);          // ciphertext (51 byte)

class ui {
  static diffuse(e){
    const t=new Uint8Array(16);
    for(let n=0;n<16;n++){
      const s=e[n], r=(s<<3|s>>5)&255;        // rotl8(s,3)
      t[n] = r ^ e[(n+1)%16] ^ e[(n+5)%16];
    }
    return t;
  }
  static transform(e){            // <-- SPN 4 ronde
    let t=Uint8Array.from(e);
    for(let n=0;n<4;n++){
      const s=Hc[n];
      for(let a=0;a<16;a++){ t[a]^=s[a]; t[a]=Gc[t[a]]; }  // AddRoundKey -> SubBytes
      t=this.diffuse(t);                                    // Diffuse
    }
    return t;                     // TIDAK ada key-add final
  }
  static async execute(e){
    const n=new TextEncoder().encode(e.trim());
    if(n.length!==16) return {error:"INVALID KEY LENGTH ..."};
    const s=this.transform(n);
    // valid jika s === Wc, lalu decryptPayload(n)
  }
  static async decryptPayload(e){ /* keystream SHA-256 counter mode, lihat §4 */ }
}
```

### Arsitektur MNC-SPN-16

- **Blok**: 16 byte (128-bit), **4 ronde**.
- **Tiap ronde**: `AddRoundKey` → `SubBytes (AES S-box)` → `Diffuse`.
- **Diffuse**: `out[i] = rotl8(in[i], 3) ^ in[(i+1)%16] ^ in[(i+5)%16]` — **linear atas GF(2)**.
- **Round key `Hc` bersifat KONSTAN** (bukan diturunkan dari key). Konsekuensinya: `transform()` adalah **permutasi tetap** dan **bisa dibalik langsung** — tidak perlu brute-force.
- Verifikasi = `transform(key) === Wc`. Artinya **key = plaintext** yang menghasilkan target signature.

---

## 2. Membalik SPN (recovery key)

Karena semua komponen invertibel, cukup jalankan `transform` **mundur** dari `Wc`. Untuk tiap ronde (dari ronde 3 ke 0):

```
state = inv_diffuse(state)     # balik layer difusi
state = inv_sbox[state]        # balik SubBytes (inverse AES S-box)
state = state XOR Hc[n]        # balik AddRoundKey
```

### Membalik Diffuse (eliminasi Gauss-Jordan GF(2))

Difusi bersifat linear dan `diffuse(0) = 0` (tanpa konstanta), jadi bisa direpresentasikan sebagai matriks biner **128×128**. Kolom ke-*j* diperoleh dengan meng-`diffuse` vektor basis (hanya bit ke-*j* yang menyala). Matriks itu di-invers dengan Gauss-Jordan atas GF(2), lalu:

```
input_bits = M_inv · output_bits   (mod 2)
```

### inverse S-box

Dibangun dari S-box maju: `inv_sbox[Gc[i]] = i`.

Menjalankan `inv_transform(Wc)` menghasilkan:

```
key (hex)   : 4d4e435f4c554e41525f323039315f58
key (ascii) : MNC_LUNAR_2091_X
```

Self-check: `transform("MNC_LUNAR_2091_X") == Wc` ✅ — kebetulan key-nya ASCII rapi (`length === 16` juga lolos).

---

## 3. Menurunkan Keystream & Dekripsi Payload

`decryptPayload` memakai **SHA-256 dalam counter mode**, di-key oleh 16-byte key yang sama:

```js
// keystream[block n] = SHA-256( key(16 byte) || counter_be32(n) )
const buf = new Uint8Array(key.length + 4);
buf.set(key, 0);
buf.set([n>>24&255, n>>16&255, n>>8&255, n&255], key.length);
const block = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
// plaintext[i] = ciphertext[i] ^ keystream[i]
```

XOR-kan keystream ke ciphertext 51-byte (`ss`) → dapat flag. Header divalidasi ke `KTCG{`.

---

## 4. Solver

Script lengkap ada di [`solve.py`](./solve.py). Ringkasan output:

```
$ python solve.py
Recovered key (hex)  : 4d4e435f4c554e41525f323039315f58
Recovered key (ascii): MNC_LUNAR_2091_X
FLAG                 : KTCG{M00nc2ust_l3v3l_b494sB3Rc4nd4_BagaskaraAP-Dev}
```

Verifikasi in-game (opsional) — jalankan di DevTools Console:

```js
await MNC.execute("MNC_LUNAR_2091_X")
// { valid: true, roundsPassed: 4, flag: "KTCG{...}" }
```

---

## 5. Flag

```
KTCG{M00nc2ust_l3v3l_b494sB3Rc4nd4_BagaskaraAP-Dev}
```

---

## 6. Catatan Desain & Pelajaran

**Kenapa soal ini solvable secara elegan (bukan brute-force):**
- Round key `Hc` konstan → SPN jadi permutasi keyless yang murni invertibel.
- Layer difusi linear atas GF(2) → aljabar linear (matriks 128×128) langsung membalikkannya, tanpa perlu Z3 sekalipun.
- S-box AES standar punya invers yang diketahui publik.

**Kalau ingin dibuat lebih berat:** jadikan *key schedule* bergantung pada key (round key = fungsi non-linear dari key), tambah key-add final, atau ganti difusi dengan MDS matrix + lebih banyak ronde — sehingga inversi langsung tidak lagi memungkinkan dan pemain terpaksa meet-in-the-middle / analisis diferensial.

---
*Writeup oleh Bagaskara Amukti Palapa (@BagaskaraAP-Dev).*
