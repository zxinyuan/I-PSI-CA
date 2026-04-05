# Bloom Filter Construction in Bernoulli Honeywords

## 1. Overview

The paper uses a **Bloom filter** to *implicitly represent a huge set of honeywords* (instead of explicitly storing them).

Instead of enumerating passwords:
- Each possible password is included as a honeyword **with probability \( p_h \)**.
- This is achieved via a randomized Bloom filter configuration.

---

## 2. Bloom Filter Structure

A Bloom filter is defined as:

- A set of **k hash functions**:
  \[
  F = \{f_1, f_2, ..., f_k\}, \quad f_i : \{0,1\}^v \rightarrow \{1, ..., b\}
  \]
- A **bit set / index set**:
  \[
  B \subseteq \{1, ..., b\}
  \]

Each element maps to **k positions** in the range \([1, b]\).

---

## 3. How Passwords Are Inserted (Bit Setting)

### Step 1: Hash the password
- A password \( \pi \) is first hashed using:
  \[
  H : \{0,1\}^* \rightarrow \{0,1\}^v
  \]
- This hash function is modeled as a **random oracle** (can be salted).

---

### Step 2: Apply k hash functions
- Compute:
  \[
  F(H(\pi)) = \{ f_1(H(\pi)), ..., f_k(H(\pi)) \}
  \]

---

### Step 3: Set bits
- Insert by updating:
  \[
  B \leftarrow B \cup F(H(\pi))
  \]

So:
- Each password sets **k positions** in the Bloom filter.
- Membership test checks whether all k positions are set.

---

## 4. Membership Test

A password \( \pi \) is considered “in the set” if:

\[
F(H(\pi)) \subseteq B
\]

This may produce **false positives**, which is intentional here.

---

## 5. How the Bloom Filter Is Generated (Key Insight)

Unlike standard Bloom filters, here the filter is **not built from a list of elements**.

Instead:

### Step 1: Choose hash functions randomly
- The set \( F = \{f_i\} \) is chosen uniformly at random.

---

### Step 2: Choose bit set B randomly

- The bit set \( B \) is randomly sampled such that:

1. **Real password is always included**:
   \[
   H(\hat{\pi}) \in_b \langle F, B \rangle
   \]

2. **Bloom filter density enforces Bernoulli probability**:
   \[
   |B| = (p_h)^{1/k} \cdot b
   \]

   This ensures:
   \[
   \Pr[\text{random password passes membership}] = p_h
   \]

   Because:
   \[
   \Pr[e \in_b \langle F, B \rangle] = \left(\frac{|B|}{b}\right)^k = p_h
   \]

---

## 6. Interpretation

This construction means:

- Every password behaves like:
  - Included with probability \( p_h \)
  - Independent of others

➡️ This **simulates Bernoulli sampling over the entire password space**.

---

## 7. Why This Works

Instead of explicitly sampling honeywords:

- The Bloom filter acts as a **probabilistic membership oracle**
- Any password:
  - Passes test with probability \( p_h \)
  - Except the real password (forced to pass)

This achieves:
- Massive compression
- No need to enumerate password space
- Clean probabilistic guarantees

---

## 8. Summary

### Bit-setting process
1. Hash password → \( H(\pi) \)
2. Apply k hash functions → positions
3. Set those positions in \( B \)

### Bloom filter generation
- Choose hash functions randomly
- Randomly choose bit density so that:
  \[
  \left(\frac{|B|}{b}\right)^k = p_h
  \]
- Ensure real password hashes are included

### Result
- Each password is implicitly a honeyword with probability \( p_h \)
