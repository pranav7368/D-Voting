# D-Voting — Poora Project, Simple Bhasha Mein (A-Z Guide)

> Ye file isliye bani hai ke aap is project ke baare mein **kuch bhi puchha jaye**, uska jawab de sakein — kya hai, kyun hai, kaise kaam karta hai, kaun kya dekh sakta hai, kaun kya nahi, aur poora vote se result tak ka safar kaise chalta hai.

---

## 1. Ek line mein — ye project kya hai

**D-Voting** ek online voting system hai jisme:
- Vote **encrypt** hota hai voter ke apne phone/browser mein, kisi server pe nahi.
- Kisi ko pata nahi chalta **kisne kisko vote diya** — na admin, na server, na hacker.
- Har vote ek **tamper-evident record** (blockchain jaisi ledger) pe seal hota hai — baad mein koi badal nahi sakta, aur badle to sabko pata chal jaata hai.
- Result nikalne ke liye **ek nahi, kam se kam 3 alag-alag log** (trustees) ko milkar chaabi lagani padti hai — akela koi bhi result nahi khol sakta.
- Har cheez **verify** ki ja sakti hai — voter apna vote, koi bhi observer poora chain — bina kisi pe "trust karo" bole.

Ye kisi real duniya ke chunav (jaise India ka General Election) ke liye ek **prototype/demo** hai — academic/hackathon project ke roop mein bana hai, par isme wahi concerns socha gaya hai jo asli election mein hote hain.

---

## 2. Sabse pehle: asli problem kya hai

Election mein do cheezein saath mein chahiye, aur ye do cheezein **ek doosre ke against** hain:

1. **Eligibility** — sirf wahi vote de jo eligible hai (voter list mein hai), aur **ek hi baar**. Isko check karne ke liye pata hona chahiye ke "ye kaun hai".
2. **Secrecy** — kisi ko pata nahi chalna chahiye ke kisne kisko vote diya. Isko preserve karne ke liye "ye kaun hai" **pata nahi hona chahiye**.

Agar ek hi system dono kaam kare (pehchaan bhi check kare, vote bhi receive kare), to wo system **dono jod sakta hai** — matlab pata chal jaayega kisne kya vote diya. Ye poore system ka sabse bada khatra hai.

### Real duniya mein iska solution kya hai?

Polling booth pe jaake dekho: ek officer aapki ID check karta hai, register pe naam mark karta hai, aur aapko **khaali ballot paper** deta hai. Uske baad aap curtain ke peeche jaake vote daalte hain. Officer ko pata hai "ye voter aaya tha", box ko pata hai "ek vote pada", **koi ek insaan ko dono pata nahi hai**.

D-Voting isi cheez ko digital tarike se karta hai — **do alag services** banake, jinke beech mein ek "blind signature" ka trick hota hai (neeche section 6 mein detail hai).

---

## 3. Is system mein kaun-kaun se "log" (parties) hain

| Party | Real duniya mein kaun | Ye system mein kya karta hai | Kya kabhi nahi dekh sakta |
|---|---|---|---|
| **Election Commission (Admin)** | EC | Candidates set karta hai, voter list (roll) banata hai, poll khol/band karta hai | Kisi ka vote, ya result decrypt karna |
| **Registration Authority (RA)** | Voter ID banane wala department | Voter ki eligibility check karta hai, ek "anonymous credential" (gupt parchi) deta hai | Voter ne kya vote diya |
| **Ballot Box + Validators** | Ballot box + polling agents | Encrypted vote receive karta hai, ledger (chain) pe seal karta hai | Voter kaun hai, vote kya hai |
| **Trustees (5 log, 3 zaroori)** | Judiciary/observers jo counting mein baithte hain | Result ki chaabi ka ek-ek tukda rakhte hain | Kisi individual ka vote (sirf total decrypt hota hai) |
| **Voter** | Aam nagrik | Apna vote encrypt karke bhejta hai | — |

**Sabse important baat**: kisi ek party ke paas do cheezein saath mein nahi hain jo use "kisne kisko vote diya" jodne de sakein. Yahi poore design ka core idea hai.

---

## 4. Poora tech stack (kya-kya use hua hai)

| Cheez | Kya use hua | Kyun |
|---|---|---|
| Language | **TypeScript**, seedha Node 22+ pe chalta hai | Node ka naya feature "type stripping" — matlab **build step ki zaroorat nahi**. Jo code likha, wahi chalta hai — audit karna aasan |
| Cryptography | **Apna khud ka code**, koi third-party crypto library nahi | Voting system mein har extra library ek extra risk hai. Sirf browser/Node ka built-in "WebCrypto" use hua hai |
| Server framework | **Hono** (halka HTTP framework) | Simple, fast, chhota |
| Ledger/Blockchain | **Apna khud ka bana hua**, koi Ethereum/Bitcoin library nahi | Poora control aur samajh — kya ho raha hai pata rehta hai |
| Frontend | **Plain HTML + JavaScript**, koi React/Vue nahi | Browser mein jo crypto chalta hai, use bhi simple aur audit-karne-layak rakha gaya |
| Database | **PostgreSQL** (production ke liye), ya memory (testing/demo ke liye) | Sirf Registration Authority ke liye — voter records ke liye |
| Testing | Node ka built-in test runner | 500+ tests, sab pass |

**Ek hi jagah build step hai**: browser ke liye crypto code ko bundle karna padta hai (kyunki browser TypeScript directly nahi chala sakta), wo bhi bina minify kiye — taaki koi bhi expert usko padh ke check kar sake ke kuch chhupaya nahi gaya.

---

## 5. Project ka folder structure (kahan kya hai)

```
D-Voting/
├── packages/
│   ├── crypto/          <- SAARI cryptography yahan hai
│   │   ├── blind-rsa/       (blind signature - eligibility ke liye)
│   │   ├── elgamal/          (encryption - vote ke liye)
│   │   ├── zkp/               (zero-knowledge proofs)
│   │   ├── threshold/        (Shamir secret sharing, trustees)
│   │   └── election/         (ballot banane/verify karne ka logic)
│   └── ledger/            <- BLOCKCHAIN/CHAIN yahan hai
│       ├── block.ts          (ek block kaisa dikhta hai)
│       ├── merkle.ts          (Merkle tree - proof ke liye)
│       ├── validator.ts       (kaun sign kar sakta hai)
│       └── chain.ts            (poori chain, append-only)
│
├── services/
│   ├── registration/      <- Registration Authority (RA)
│   ├── ballot-box/          <- Ballot Box + Web UI (sabse bada service)
│   │   └── public/            (voter, admin, verify, results, CHAIN EXPLORER)
│   ├── trustee/              <- Har trustee ka apna process
│   └── validator/            <- Har validator (chain sign karne wala) ka process
│
├── scripts/
│   └── dev-up.ts            <- Ek command se poora system chalu karta hai
│
└── docs/                    <- Design decisions, limitations, sab likha hua
```

---

## 6. Cryptography — har concept, simple bhasha mein

Ye section thoda technical hai, par maine har cheez ko roz-marra ki misaal se samjhaya hai.

### 6.1 Blind Signature (RFC 9474) — "andhi mohar"

**Problem**: RA ko check karna hai ke voter eligible hai, aur RA ko ek "credential" (anonymous parchi) sign karna hai — **par RA ko pata nahi chalna chahiye ke usne KISKO ye parchi di**.

**Kaise kaam karta hai**: Socho aap ek kaagaz ko carbon-paper wale envelope mein daal dete ho. Officer envelope ke UPAR se apni mohar laga deta hai — mohar seedha kaagaz pe carbon se print ho jaati hai, par officer ne kaagaz **dekha nahi**. Baad mein aap envelope se kaagaz nikaal lete ho — usme officer ki asli mohar hai, aur officer ko pata bhi nahi ke kis kaagaz pe usne mohar lagayi thi.

Yahi digitally hota hai:
1. Voter ek random "credential" banata hai (apne phone/browser mein).
2. Usko "blind" (chhupa) karta hai — ek random number se multiply karke.
3. RA ko bhejta hai. RA check karta hai voter eligible hai ya nahi, aur agar haan, to us **blinded** (chhupe) value pe sign kar deta hai — usko asal credential dikhta hi nahi.
4. Voter apne browser mein "unblind" karta hai — random number hata deta hai.
5. Ab voter ke paas ek **valid signature** hai, jo RA ne di, par RA ko yaad nahi ke kisko di — kyunki usne kabhi asal credential dekha hi nahi.

**Kyun important hai**: Ye link (voter ↔ credential) **mathematically kabhi bana hi nahi**. Ye koi "promise" nahi hai ke RA data delete kar dega — ye ek **maths ka fact** hai ke us data mein kabhi wo information thi hi nahi.

**Ek chhota par zaroori detail**: Raw signature use nahi hota, "PSS encoding" use hoti hai — warna do voters milkar apne signatures ko combine karke ek **naya, kabhi-issue-na-hua credential** bana sakte the (isko "existential forgery" kehte hain). PSS encoding isko rok deti hai.

### 6.2 ElGamal Encryption — vote ko chhupana

Vote ko encrypt karna hai taaki:
- Sirf padhne wale ko dikhe ke ye "0" ya "1" hai (candidate ko vote diya ya nahi) — aur wo bhi sirf jab TRUSTEES decrypt karein.
- **Sabhi votes ko JODA ja sake bina kisi ek ko decrypt kiye** — isko "homomorphic" property kehte hain.

**Homomorphic ka matlab**: Agar Vote A = "1 for Alice" (encrypted) aur Vote B = "0 for Alice" (encrypted), to `EncryptedA + EncryptedB` (encrypted state mein hi jod ke) = "1 for Alice" ka encryption — bina kisi individual vote ko dekhe! Ye jaise ek band dabbe mein 2 sikke daalo, aur bina dabba khole pata chal jaaye total kitna hai.

Isliye **kabhi bhi kisi individual ka vote decrypt nahi hota** — sirf final SUM decrypt hota hai, aur wo bhi sirf jab poll band ho jaaye.

### 6.3 Zero-Knowledge Proof (ZKP) — "prove karo bina dikhaye"

Jab voter apna encrypted vote bhejta hai, to ballot box ko ye pata hona chahiye:
- Ye vote **valid** hai — matlab har candidate ke liye ciphertext sirf "0" ya "1" hi encrypt kar raha hai (na koi negative number, na "5", jisse koi cheating kare).

Par ballot box ko ye **decrypt karne ka koi rasta nahi hai** (usके paas chaabi hi nahi). To voter ek **Zero-Knowledge Proof** bhejta hai — ek mathematical proof jo saabit karta hai "ye encrypted value 0 ya 1 mein se koi ek hai" **bina batye kaunsa hai**.

Simple misaal: Socho aapko prove karna hai ke aapke paas ek tale ki chaabi hai, bina tala khole ya chaabi dikhaye. Aap tale ko dusri jagah lock-unlock karke dikha sakte ho — is process se saamne wala convince ho jaata hai ke chaabi hai, par chaabi khud nahi dikhti. ZKP isी tarah "maths mein" hota hai.

### 6.4 Threshold Decryption — "chaabi ke tukde"

Election ki "master key" (jisse final result decrypt hota hai) kabhi **pura kisi ek ke paas nahi hota**. Isko **Shamir Secret Sharing** algorithm se 5 tukdon mein baant diya jaata hai, aur kam se kam **3 tukde** milna zaroori hai result kholne ke liye.

- Agar sirf 1-2 trustee milte hain — result nahi khulega.
- Agar 3 ya usse zyada milte hain — result khul jaata hai, par **poora master key kisi ek jagah kabhi assemble nahi hota** — maths ke through "exponent mein" combine hota hai.

**Pedersen DKG** (Distributed Key Generation) — is election ki chaabi khud banti hai 5 trustees milke, **koi bhi ek insaan (dealer) poori chaabi kabhi nahi dekhta**, shuru se hi.

**Chaum-Pedersen Proof**: har trustee apna decryption ke saath ek proof deta hai ke "maine wahi hissa use kiya jo maine setup ke time commit kiya tha" — agar koi trustee cheat karke galat number bhej de, ye proof usko **turant pakad leta hai, aur uska naam bhi bata deta hai**.

### 6.5 Merkle Tree — "ek hash se sabka proof"

Ek block mein kaafi entries (ballots) hoti hain. Merkle Tree ek tarika hai jisse **koi bhi ek entry ke "asli hone" ka proof** sirf kuch hashes se ho jaata hai — poora block download kiye bina.

Isse voter ko "aapka vote record mein hai" — ye sirf apne ballot + kuch hashes se prove ho jaata hai, poori chain download karne ki zaroorat nahi.

### 6.6 Ed25519 Signatures — validators ki mohar

Har block ko **kam se kam 3 validators** (alag-alag organizations, jaise EC, press, university) apni **digital signature** se sign karte hain. Ye Ed25519 algorithm use karta hai (fast aur secure).

Agar koi block sign nahi hua **quorum (3+) validators se**, to usko koi bhi observer reject kar dega apne browser mein hi — server pe trust karne ki zaroorat nahi.

### 6.7 Benaloh Cast-or-Audit — "malicious app ko pakadna"

Sabse bada dar: agar voting app (browser JS) khud dishonest ho, aur galat cheez encrypt kar de? Voter ko lagega "maine Alice ko vote diya" par app ne Bob ko encrypt kar diya.

**Solution**: App pehle ballot **prepare** karta hai (encrypt kar leta hai) aur ek "fingerprint" dikhata hai. Ab voter ke paas 2 option hote hain:
1. **Cast** — isi ballot ko bhej do.
2. **Check (Audit)** — app se "randomness" (jisse encryption hua) reveal karwao, aur khud check karo ke jo encrypt hua wo sahi hai ya nahi.

**Trick**: App ko pata nahi hota voter kaunsa option choose karega — isliye agar app cheat karega, to usse pakde jaane ka risk hamesha rehta hai. Jo bhi ballot **audit ho jaata hai wo cast nahi ho sakta** (kyunki uska secret ab public ho gaya) — voter fresh ballot banata hai.

---

## 7. Poora flow, shuru se aakhir tak (A → Z)

### Step 0 — Setup (Admin/Election Commission)
1. Admin **candidates** set karta hai (kitne, kaunse naam).
2. Admin **naam** set kar sakta hai election ka (jaise "General Election 2026") — ye sirf display ke liye hai.
3. Admin **voters ko roll mein add** karta hai — har voter ko ek **roll ID + enrolment code** (polling card jaisa) milta hai. Ye code **sirf ek baar dikhta hai** — server sirf uska HMAC (hash) store karta hai.
4. Admin **roll ko FREEZE** karta hai — matlab ab koi naya voter add nahi ho sakta. Freeze karte hi ek **"commitment"** (hash) milta hai — ye publish kiya ja sakta hai taaki koi bhi confirm kar sake roll badla nahi gaya.
5. Admin **poll OPEN** karta hai — isी waqt **poora election ka data ek "genesis block" (Block #0) mein seal ho jaata hai**: candidates, roll commitment, trustee list, validator list — sab kuch. **Iske baad kuch bhi change nahi ho sakta.**

### Step 1 — Voter Registration
1. Voter apna roll ID + enrolment code browser mein daalta hai.
2. Browser **seedha Registration Authority (RA) ko** request bhejta hai — **Ballot Box ke through NAHI** (ye bahut important hai — isse RA aur Ballot Box kabhi ek doosre ka data jod nahi sakte).
3. RA check karta hai ke code sahi hai. Agar haan, to ek **temporary token** deta hai.
4. Browser ek anonymous "credential" banata hai, usko **blind** karta hai (section 6.1), aur RA se sign karwata hai.
5. Browser **unblind** karta hai — ab uske paas ek valid, signed, **anonymous** credential hai.

### Step 2 — Vote Encrypt Karna (Browser Mein)
1. Voter candidate choose karta hai.
2. Browser **khud** apne andar vote ko ElGamal se encrypt karta hai — server ko kabhi plain vote nahi bhejta.
3. Browser ek Zero-Knowledge Proof banata hai ("ye vote valid hai").
4. Browser ek "fingerprint" (commitment) dikhata hai voter ko.

### Step 3 — Cast ya Audit
- **Cast**: Ballot + credential + signature Ballot Box ko bhejta hai.
- **Audit** (optional): Randomness reveal karta hai, khud check karta hai app honest hai ya nahi. Agar audit kiya, wo ballot cast nahi ho sakta — fresh ballot banana padega.

### Step 4 — Ballot Box Accept Karta Hai
Ballot Box do cheezein check karta hai (bina vote ya voter dekhe):
1. **Eligibility**: credential pe RA ka valid signature hai ya nahi.
2. **Validity**: ZK proof sahi hai ya nahi (vote 0/1 hi hai).

Dono sahi hain to ballot **pending list** mein jaata hai.

### Step 5 — Block Sealing (Chain Banna)
Jab kaafi ballots pending ho jaate hain (ya turant, demo mein), ek naya **block** banta hai:
1. Sab pending entries ka **Merkle Root** banta hai.
2. Block header banta hai — height, previous block ka hash, Merkle root, timestamp, proposer ka naam.
3. Ek validator (round-robin turn se) is header ko **propose** karta hai.
4. Har validator apni copy pe **independently check** karta hai (sab kuch dobara verify karta hai — ballots proofs bhi) aur agar sahi hai to **apni signature** deta hai.
5. Jab **quorum (jaise 3 of 4)** validators sign kar dete hain, block **finalize** ho jaata hai aur chain mein add ho jaata hai.

**Ye "chain" hai kaise**: Har block ke header mein **pichhle block ka hash** hota hai. Isliye agar koi purana block change kare, to uska hash badal jaayega, jisse agla block "toot jaayega" (link match nahi karega) — **isliye tampering turant pakdi jaati hai.**

### Step 6 — Poll Close
Admin poll band karta hai — ye bhi ek **entry chain pe seal** hoti hai (memory mein sirf flag nahi, isliye restart karne pe bhi band hi rahega).

### Step 7 — Trustee Decryption Ceremony
1. Ballot Box saare ballots ko **homomorphically jod** deta hai (per-candidate total, still encrypted).
2. Har trustee (apne alag process/console se):
   - Poori chain download karta hai, **khud verify** karta hai (hash, links, signatures).
   - Totals ko **khud bhi recompute** karta hai chain ke ballots se — Ballot Box ke bataye number pe trust nahi karta.
   - Sab sahi mila to apna **key ka tukda** apply karta hai, aur ek proof deta hai.
3. Jab **3 trustees** apna hissa de dete hain, totals **decrypt ho jaate hain** — final count nikal aata hai.
4. Result, saare proofs ke saath, chain pe **seal** ho jaata hai.

### Step 8 — Verification (Koi Bhi Kar Sakta Hai)
- **Voter** apna tracking code se check kar sakta hai ballot record mein hai — browser khud Merkle proof + signatures verify karta hai.
- **Koi bhi observer** `/chain` page (Chain Explorer) pe jaake **poori chain** dekh sakta hai — har block ka hash, link, aur signature browser khud check karta hai.
- **Koi bhi** `/results` pe jaake **independent recount** dekh sakta hai — sab ballots dobara verify, totals dobara jode, trustee proofs dobara check.

---

## 8. Chain kaise structure mein bani hoti hai (thoda deep)

Ek **block** mein ye cheezein hoti hain:

```
Block
├── Header
│   ├── height              (kaunsa number block hai — 0, 1, 2...)
│   ├── electionId
│   ├── previousHash          (pichle block ka hash — YAHI CHAIN BANATA HAI)
│   ├── merkleRoot            (sab entries ka combined hash)
│   ├── entryCount
│   ├── timestamp
│   ├── proposer               (kis validator ne banaya)
│   └── view                    (consensus round number)
├── Entries[]                  (asli data)
│   ├── kind: "election-config"     <- Block 0 mein, poora election setup
│   ├── kind: "ballot"                <- ek cast vote (encrypted)
│   ├── kind: "spoiled-ballot"        <- audit ki hui ballot (public)
│   ├── kind: "election-closed"       <- poll band hone ka record
│   └── kind: "tally-result"           <- final result, proofs ke saath
└── Attestations[]              (validators ki digital signatures — quorum)
```

**Block ka hash** kaise banta hai: Header ke saare fields ko ek fixed, "canonical" tarike se bytes mein convert karke, SHA-256 lagaya jaata hai. (JSON use nahi hota hashing ke liye, kyunki JSON ka format thoda alag-alag ho sakta hai — isliye ek "fixed-format encoder" use hota hai jisse har baar EXACT same bytes banein.)

**Chain kaise "link" hoti hai**: Block 5 ke header mein "previousHash" field hoti hai — usme Block 4 ka poora recomputed hash hota hai. Agar koi Block 4 mein kuch change kare, Block 4 ka hash badal jaayega, aur Block 5 ka "previousHash" ab match nahi karega — **is mismatch se hi tampering pakdi jaati hai**, kisi ek insaan ke bharose nahi.

---

## 9. Kaun kya verify karta hai, kaise

| Kaun | Kya verify karta hai | Kaise |
|---|---|---|
| **Voter** | Mera ballot record mein hai | Apna ballot ka Merkle proof + validator signatures apne browser mein check karta hai |
| **Trustee** | Jo totals mujhe decrypt karne ko diye gaye, wo sahi hain | Poori chain download karke, khud sab ballots jod ke total nikalta hai, compare karta hai |
| **Koi bhi observer (Chain Explorer)** | Poora chain genuine hai | Har block ka hash recompute, previous se link check, signatures check — sab browser mein |
| **Koi bhi (Results page)** | Final result sahi hai | Chain se saare ballots dobara verify, totals dobara jode, trustee proofs dobara check, announced number se match |
| **Ballot Box** | Ballot valid hai, credential eligible hai | ZK proof check, RA ka signature check |
| **Validators** | Block valid hai | Har ballot ka proof dobara check karta hai, tab hi sign karta hai |

**Sabse bada principle jo poore project mein baar-baar aata hai**: **"Kisi bhi party ke keh dene pe bharosa nahi karo — khud calculate karo."** Isliye har jagah "independent verification" likha hua milega.

---

## 10. Security guarantees — kya nahi ho sakta

| Ye NAHI ho sakta | Kyun nahi ho sakta |
|---|---|
| Admin kisi ka vote dekh le | Ballot Box ke paas decryption key hi nahi hai |
| Admin result akela khol le | Result 3+ trustees ke bina decrypt nahi hota |
| RA jaan le voter ne kya vote diya | RA aur Ballot Box alag services hain, kabhi baat nahi karte ek doosre se seedha; credential blind hota hai |
| Koi purana vote change kar de bina pakde | Chain ka hash-link tootega, turant dikh jaayega |
| Election khulne ke baad candidate badal jaaye | Poora config Block 0 mein seal hota hai — edit route hi nahi bachta |
| Band poll restart karke dobara khul jaaye | "Closed" chain pe entry hai, memory ki flag nahi |
| Ek voter do baar vote de (bina pakde) | RA ek hi credential deta hai per person; Ballot Box ek credential se ek "current" vote hi maanta hai |
| Malicious voting app pakda na jaaye | Benaloh audit — app ko pata nahi voter check karega ya nahi |
| Trustee galat number decrypt karke result bigaad de | Chaum-Pedersen proof — turant pakda jaata hai, uska naam bhi pata chal jaata hai |

---

## 11. Jo cheezein honestly "limitation" hain (chhupayi nahi gayi)

Ye project **imaandari se apni kamiyan bhi batata hai** — viva/interview mein ye sabse zyada respect milne wali baat hai:

1. **Fake voter add karna** — agar Admin roll freeze karne se PEHLE fake naam daal de, koi bhi cryptography usko nahi pakad sakti (kyunki wo naam "legitimately" committed ho jaata hai). Real duniya mein iska solution hai: roll **publish** karo, sabko dekhne do, objection ka time do.
2. **3+ trustees mil jaayein to individual ballot decrypt ho sakti hai** — isliye trustees genuinely **alag-alag, competing interests** wale log hone chahiye (jaise ruling party ka agent + opposition party ka agent + judiciary), na ke sab ek hi commission ke log.
3. **Coercion (dabaav)** — voter dobara vote de sakta hai (sirf last vote count hota hai), par ek coercer dekh sakta hai ke "iska credential ne baad mein phir vote diya" (content nahi dikhta, par "kuch hua" ye dikh jaata hai).
4. **Device/browser reload ho jaaye vote se pehle** — credential sirf tab ki memory mein hota hai, doosri baar nahi milega. Isliye UI mein warning hai: "Vote cast hone tak tab band na karein."
5. **Everlasting privacy nahi hai** — encrypted votes hamesha public rehte hain chain pe. Agar 30 saal baad koi encryption todne wali technology (quantum computer) aa jaaye, purane votes theoretically khul sakte hain. (Yeh Helios jaisi har E2E-verifiable system ki limitation hai, sirf D-Voting ki nahi.)

---

## 12. Har service, port, aur kaam — reference table

| Service | Port (demo mein) | Kaam |
|---|---|---|
| Registration Authority | 8081 | Voter register karta hai, blind-signed credential deta hai |
| Ballot Box + Web UI | 8082 | Vote accept karta hai, poori website serve karta hai (`/vote`, `/verify`, `/results`, `/admin`, `/chain`) |
| Validators (4) | 8090-8093 | Har ek apna chain-copy rakhta hai, blocks sign karta hai |
| Trustees (5) | 8100-8104 | Har ek apna key-share rakhta hai, apna console hai jahan se decrypt mein contribute karta hai |

**Web pages** (Ballot Box pe):
- `/vote` — voter yahan se vote karta hai
- `/verify` — koi bhi apna tracking code daal ke check kar sakta hai
- `/results` — final result + independent recount
- `/admin` — Election Commission ka console (candidates, roll, open/close)
- `/chain` — **Chain Explorer** — poora ledger, block-by-block, browser khud verify karta hai

---

## 13. Kaise chalayein, test karein, demo dein

```bash
npm install                # sab dependencies install
npm run build:web          # browser ke liye crypto bundle banao
npm test                   # 500+ tests chalao
npm run dev                # poora system chalao (11 processes)
```

`npm run dev` chalane ke baad terminal mein saare URLs aur tokens print honge. Phir:
1. `/admin` pe jaake candidates set karo, voters enrol karo, roll freeze karo, poll open karo.
2. `/vote` pe jaake (voter ka card use karke) vote daalo.
3. `/admin` se poll close karo.
4. 3 trustee consoles kholke (alag-alag ports pe) apna share do.
5. `/results` ya `/chain` pe jaake result aur poora record dekho.

Ek **narrated demo** bhi hai jo sab kuch automatically dikhata hai, ek attack bhi karke dikhata hai (aur pakdi jaati hai):

```bash
node services/ballot-box/src/scripts/full-election-demo.ts 12
```

---

## 14. Common sawaal jo puche ja sakte hain (FAQ)

**Q: Blockchain kyun use kiya, jab cryptography hi security de rahi hai?**
A: Blockchain yahan security ka source **nahi** hai — wo cryptography (blind signature, ElGamal, ZK proofs) se aati hai. Blockchain sirf **tamper-evidence** ke liye hai — matlab agar koi record ke saath cheating kare, to **sabko pata chal jaaye**. (Ye ek research-based decision hai — MIT/Harvard ke paper ne dikhaya hai ke blockchain ko akela security mechanism maanna khatarnaak hai.)

**Q: Agar Election Commission khud corrupt ho jaaye?**
A: EC roll mein fake naam daal sakta hai (agar freeze se pehle) — ye cryptography nahi pakad sakti. Par EC **result nahi khol sakta akela** (trustees chahiye), **kisi ka vote nahi dekh sakta** (usके paas decryption key nahi), aur **jo bhi karega wo chain pe record hoga, publicly dikhega**. Isliye: "EC cheat kar sakta hai, par chhup nahi sakta."

**Q: Agar ballot box hi jhooth bole trustees ko?**
A: Har trustee khud chain download karke, khud ballots jodkar total nikalta hai — Ballot Box ke bataye number ko trust nahi karta. Agar mismatch ho, trustee **refuse kar deta hai** apna share dene se.

**Q: Ek voter do baar vote de sakta hai kya?**
A: Haan, **de sakta hai** (jaan-boojh kar allow kiya gaya hai — coercion se bachne ke liye, taaki dabaav mein vote diya voter baad mein chupke se sahi vote de sake), par sirf **last vote count** hota hai. Pehle wale "superseded" ho jaate hain.

**Q: Encryption kaise pata chalta hai valid hai, agar decrypt nahi kar sakte?**
A: Zero-Knowledge Proof se — voter ek mathematical proof deta hai jo saabit karta hai "yeh sirf 0 ya 1 hai" bina batye kaunsa hai (section 6.3 dekho).

**Q: Naam (election name) aur electionId mein farak kya hai?**
A: `electionId` (jaise `dvoting-local-2026`) **technical identifier** hai — har proof, har signature, har check isी se bandha hai, ye kabhi badal nahi sakta. `name` (jaise "General Election 2026") sirf **dikhane ke liye** hai, kisi cryptography mein use nahi hota — sirf UI mein achha dikhne ke liye hai.

**Q: Chain Explorer kya extra dikhata hai jo results page nahi dikhata?**
A: Results page sirf **final number** aur uska recount dikhata hai. Chain Explorer **har ek block** dikhata hai — kaun sa validator ne sign kiya, kab, aur agar koi block spoiled-ballot ya config hai to uska poora decode bhi dikhata hai. Ye "kaise bana" dikhata hai, results page "kya bana" dikhata hai.

---

## 15. Ek-line summary jo yaad rakhne layak hai

> **"Koi bhi party doosri party ki jaankari se apna knowledge jod nahi sakti — aur jo bhi record chain pe hai, wo tamper-evident hai. Result nikalne ke liye kam se kam 3 independent trustees chahiye, aur har cheez ka independent verification khud kisi ke bharose nahi, apne calculation se ho sakta hai."**

Yahi is poore D-Voting system ka dil hai.
