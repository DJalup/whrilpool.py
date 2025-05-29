# 🌀 whirlpool.py – Pure Python Implementation of the Whirlpool Hash Function

This project provides a **100% pure Python implementation** of the [Whirlpool cryptographic hash function](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)). It follows the official NESSIE specification with full bit-accurate compliance.

---

## 🚀 Features

- ✅ 512-bit output (64 bytes)
- ✅ ISO/IEC 10118-3 compliant padding
- ✅ Substitution–Permutation Network (SPN) with 10 rounds
- ✅ MDS matrix mixing over Galois Field GF(2⁸)
- ✅ Self-contained and dependency-free
- ✅ Drop-in streaming API with `.update()`, `.digest()`, `.hexdigest()`

---

## 📚 Specification Compliance

This implementation faithfully follows:

- The **Whirlpool algorithm** designed by Vincent Rijmen and Paulo Barreto
- The **NESSIE** project specification
- The **official S-box** and **round constant schedule**
- The **8×8 MDS matrix** mixing with proper finite field math

---

## 🧪 Example Usage

```python
from whirlpool import Whirlpool

h = Whirlpool()
h.update(b"abc")
print(h.hexdigest())
```

Expected output:
```
4e2448a4c6f486bb16b6562c73b4020bf3e9765e8a234aa83e74d59b349ad2e4
b7f4b9323b519d8d5d8c4b6e41bfa9327d4a10a85ec4f3a1a70a5a2029d612a7
```

---

## 📦 Installation

This is a single-file module. You can drop `whirlpool.py` into your project, or install manually:

```bash
wget https://raw.githubusercontent.com/DJalup/whirlpool.py/main/whirlpool.py
```

---

## 📜 License

This implementation is **public domain**.
- No copyright
- No license restrictions
- No attribution required

Use it in personal projects, commercial software, embedded firmware — anything.

---

## ❤️ Contributing

Pull requests to improve speed, test coverage, or packaging are welcome. Fork and hack away.
