"""Generate the editable academic report for the D-Voting repository.

This file is intentionally kept with the report so cover-page placeholders and
institutional formatting can be changed without rebuilding the application.
"""
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.text import WD_COLOR_INDEX
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

OUT = Path(__file__).with_name("D-Voting-Project-Report.docx")
doc = Document()
sec = doc.sections[0]
sec.page_width, sec.page_height = Inches(8.5), Inches(11)
sec.top_margin = Inches(.82)
sec.bottom_margin = Inches(.72)
sec.left_margin = Inches(1.0)
sec.right_margin = Inches(.9)
sec.header_distance = Inches(.36)
sec.footer_distance = Inches(.38)

styles = doc.styles
normal = styles["Normal"]
normal.font.name = "Times New Roman"
normal.font.size = Pt(11.5)
normal.font.color.rgb = RGBColor(31, 38, 47)
normal.paragraph_format.line_spacing = 1.35
normal.paragraph_format.space_after = Pt(7)
normal.paragraph_format.widow_control = True

for name, size, before, after in [
    ("Title", 20, 0, 20), ("Heading 1", 16, 16, 9),
    ("Heading 2", 13, 13, 6), ("Heading 3", 11.5, 9, 4),
]:
    s = styles[name]
    s.font.name = "Times New Roman"
    s.font.size = Pt(size)
    s.font.bold = True
    s.font.color.rgb = RGBColor(22, 39, 64)
    s.paragraph_format.space_before = Pt(before)
    s.paragraph_format.space_after = Pt(after)
    s.paragraph_format.keep_with_next = True
    s.paragraph_format.widow_control = True

for name in ["Caption", "Quote"]:
    styles[name].font.name = "Times New Roman"
    styles[name].font.size = Pt(10)

if "Table Text" not in styles:
    tstyle = styles.add_style("Table Text", WD_STYLE_TYPE.PARAGRAPH)
else:
    tstyle = styles["Table Text"]
tstyle.font.name = "Times New Roman"
tstyle.font.size = Pt(9.5)
tstyle.paragraph_format.line_spacing = 1.13
tstyle.paragraph_format.space_after = Pt(2)

header = sec.header.paragraphs[0]
header.text = "D-Voting  |  Academic Project Report"
header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
header.style = "Caption"
footer = sec.footer.paragraphs[0]
footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
footer.style = "Caption"
footer.add_run("D-Voting  •  ")
fld = OxmlElement("w:fldSimple")
fld.set(qn("w:instr"), "PAGE")
footer._p.append(fld)

def para(text="", style=None, align=None):
    p = doc.add_paragraph(style=style)
    if align is not None:
        p.alignment = align
    p.add_run(text)
    return p

def body(text):
    for p in text.strip().split("\n\n"):
        if p.strip():
            para(" ".join(p.strip().split()))

def heading(text, level=1):
    doc.add_heading(text, level=level)

def page():
    doc.add_page_break()

def table(headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    if widths:
        for i, w in enumerate(widths):
            t.columns[i].width = Inches(w)
    for i, h in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = h
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        for p in cell.paragraphs:
            p.style = "Table Text"
            for run in p.runs:
                run.bold = True
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:fill"), "E9EEF4")
        tcPr.append(shd)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = str(val)
            cells[i].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            for p in cells[i].paragraphs:
                p.style = "Table Text"
    doc.add_paragraph()
    return t

def caption(text):
    p = para(text, "Caption", WD_ALIGN_PARAGRAPH.CENTER)
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(10)

def chapter(num, title, overview):
    page()
    heading(f"Chapter {num}  {title}", 1)
    body(overview)

def sub(title, text):
    heading(title, 2)
    body(text)

def bullets(items):
    for item in items:
        p = doc.add_paragraph(style="List Bullet")
        p.add_run(item)

def numbered(items):
    for item in items:
        p = doc.add_paragraph(style="List Number")
        p.add_run(item)

# Cover
for _ in range(3): para()
p = para("PROJECT REPORT", align=WD_ALIGN_PARAGRAPH.CENTER)
p.runs[0].font.size = Pt(17); p.runs[0].bold = True
para("ON", align=WD_ALIGN_PARAGRAPH.CENTER)
p = para("D-VOTING", align=WD_ALIGN_PARAGRAPH.CENTER)
p.runs[0].font.size = Pt(26); p.runs[0].bold = True
p = para("An End-to-End Verifiable Electronic Voting System with a Permissioned Audit Ledger", align=WD_ALIGN_PARAGRAPH.CENTER)
p.runs[0].font.size = Pt(14)
for _ in range(2): para()
para("Submitted in partial fulfilment of the requirements for the award of", align=WD_ALIGN_PARAGRAPH.CENTER)
para("[DEGREE / PROGRAMME NAME]", align=WD_ALIGN_PARAGRAPH.CENTER)
para("in [DEPARTMENT / DISCIPLINE]", align=WD_ALIGN_PARAGRAPH.CENTER)
for _ in range(2): para()
table(["Submitted by", "Under the guidance of"], [["[STUDENT NAME]\n[ROLL NUMBER]", "[GUIDE NAME]\n[DESIGNATION]"]], [3.3, 3.3])
for _ in range(2): para()
para("[COLLEGE / INSTITUTION NAME]", align=WD_ALIGN_PARAGRAPH.CENTER)
para("[UNIVERSITY NAME]", align=WD_ALIGN_PARAGRAPH.CENTER)
para("[CITY, STATE]", align=WD_ALIGN_PARAGRAPH.CENTER)
para("Academic Year: [20XX–20XX]", align=WD_ALIGN_PARAGRAPH.CENTER)

page(); heading("Certificate", 1)
body("This is to certify that the project report entitled “D-Voting: An End-to-End Verifiable Electronic Voting System with a Permissioned Audit Ledger” is submitted by [STUDENT NAME], [ROLL NUMBER], to [COLLEGE / INSTITUTION NAME] in partial fulfilment of the requirements for [DEGREE / PROGRAMME NAME] during academic year [20XX–20XX]. The work described in this report has been presented for academic evaluation under the guidance of [GUIDE NAME].")
body("The project code, observations and statements in this report should be reviewed by the guide and department before institutional approval. This page is a template for their certification; no signature is implied by this document.")
for _ in range(5): para()
table(["Guide", "Head of Department", "External Examiner"], [["Signature: __________\nName: [GUIDE NAME]\nDate: __________", "Signature: __________\nName: [HOD NAME]\nDate: __________", "Signature: __________\nName: [EXAMINER NAME]\nDate: __________"]])
para("Institutional seal: ____________________")

page(); heading("Declaration", 1)
body("I, [STUDENT NAME], [ROLL NUMBER], declare that this report is prepared for academic submission on the D-Voting project. The technical description is based on the source code, repository documentation and verification evidence available at the time of preparation. Published ideas and standards are acknowledged in the references. I will review and correct any institution-specific wording, ownership statement and contribution details before signing this declaration.")
body("This declaration is intentionally unsigned. The student should sign it only after confirming that it accurately represents their own work and the academic rules of [COLLEGE / INSTITUTION NAME].")
for _ in range(7): para()
para("Place: [CITY]                         Signature: ____________________")
para("Date: [DATE]                          Name: [STUDENT NAME]")

page(); heading("Acknowledgements", 1)
body("I would like to thank [GUIDE NAME] for guidance and feedback during the development and study of this project. I also acknowledge the support of [DEPARTMENT NAME] and [COLLEGE / INSTITUTION NAME] for providing an academic setting in which to examine secure electronic voting. The open standards and research cited in this report helped frame the design and its limitations.")
body("This text is a placeholder for the student's own acknowledgements. It should be personalised before submission and should not imply assistance that was not actually received.")

page(); heading("Abstract", 1)
body("D-Voting is a prototype electronic voting platform designed around end-to-end verifiability. Eligible voters obtain an anonymous voting credential from a registration authority using a blind-signature protocol. A ballot is encrypted in the browser with exponential ElGamal and accompanied by zero-knowledge validity proofs. A ballot box checks the credential and proofs, while independent validators commit accepted records to a permissioned hash-chained ledger. A public bulletin board exposes blocks and Merkle inclusion proofs. After closure, trustees jointly decrypt only the homomorphic aggregate and publish evidence that allows a public recount.")
body("The project also implements a cast-or-audit challenge, re-voting with a last-valid-ballot rule, election configuration sealed at opening, and a browser interface for voting, verification, results, chain inspection and administration. Its value lies in separating ballot secrecy from ledger integrity: the blockchain is an audit layer, not the mechanism that hides a vote. The report documents the architecture, workflow, cryptographic choices, implementation, testing, threat boundaries and proposed improvements. The prototype is not presented as a production-ready public-election system; identity proofing, operational security, coercion resistance and deployment governance remain substantial concerns.")
para("Keywords: electronic voting; end-to-end verifiability; blind signatures; ElGamal; threshold decryption; permissioned ledger.")

page(); heading("Contents", 1)
# Use Word's native TOC field so page numbers are calculated from the final
# layout, rather than hard-coded against an intermediate draft.
p = doc.add_paragraph()
fld = OxmlElement("w:fldSimple")
fld.set(qn("w:instr"), 'TOC \\o "1-3" \\h \\z \\u')
r = OxmlElement("w:r")
t = OxmlElement("w:t")
t.text = "Right-click this table and choose Update Field to calculate page numbers."
r.append(t); fld.append(r); p._p.append(fld)
body("The Contents field is linked to the report headings. In Microsoft Word, right-click inside it and select Update Field, then choose Update entire table. This recalculates all page numbers after any edits.")

page(); heading("List of Figures and Tables", 1)
body("Figure 5.1  Separation of project parties and data flow\n\nFigure 6.1  Credential and ballot protocol sequence\n\nFigure 8.1  Election lifecycle state progression\n\nTable 3.1  Objectives and corresponding mechanisms\n\nTable 4.1  Functional and non-functional requirements\n\nTable 5.1  Service responsibilities\n\nTable 6.1  Cryptographic mechanisms and their role\n\nTable 7.1  Public verification artefacts\n\nTable 8.1  Interface pages and primary tasks\n\nTable 10.1  Test and verification evidence\n\nTable 11.1  Threats and residual risk\n\nTable A.1  Representative HTTP endpoints")

chapter(1, "Introduction", "Electronic voting seeks to make participation and counting convenient while preserving the legitimacy of an election. These goals are harder to combine than they appear. An ordinary web application can authenticate a user and store a selection, but the resulting database administrator may be able to read, change or correlate votes. Encrypting the database protects stored data yet does not, by itself, prove that the browser encrypted the intended choice or that the published result came from all accepted ballots. D-Voting explores these linked requirements in a working prototype.")
sub("1.1 Context and motivation", "A trustworthy election needs more than a login screen and a count. The voter must be eligible, a choice must remain secret, only valid ballots should be accepted, and the published result must be independently checkable. In an online setting, these properties span the voter device, the registration service, the ballot service, the public record and the people who control decryption. A weakness in any one part can defeat the practical election even if the remaining algorithms are sound. Research on Internet and blockchain voting therefore urges caution about equating a distributed ledger with election security [1].")
sub("1.2 Project overview", "D-Voting is a TypeScript monorepo with a cryptographic package, a ledger package and four service types: registration authority, ballot box, validator and trustee. The browser offers separate voting, verification, results, chain-inspection and administration views. The implementation uses RSA blind signatures for anonymous credentials, ElGamal encryption and validity proofs for ballots, a permissioned ledger for tamper-evident publication, and threshold decryption for the final aggregate. The system is intended as a demonstrable academic prototype, not a claim that remote voting is safe for a binding national election.")
sub("1.3 Scope of this report", "This report explains the problem and literature, records requirements, follows data through the implemented components, describes the cryptographic and ledger protocols at a level suitable for project evaluation, and examines test evidence. It also treats limitations as part of the result. Details that depend on an institution—student identity, supervisor, programme, signature and academic year—are left as explicit placeholders. Technical observations reflect the repository as inspected for this report; they should be rechecked if the application changes.")
sub("1.4 Report organisation", "Chapters 2–4 establish the background, objectives and threat model. Chapters 5–9 explain architecture, mechanisms, lifecycle, interface and implementation. Chapters 10–12 cover verification, security and future work. Chapter 13 concludes, followed by references and appendices containing an API summary, reproducibility instructions and terminology.")

chapter(2, "Background and Literature", "The design draws on the distinction between a system that merely records votes and one that offers evidence of correct processing. The literature on end-to-end verifiable voting provides mechanisms for checking ballot construction, inclusion and tallying, while security analyses of Internet voting show why those mechanisms do not eliminate malware, coercion or governance risks.")
sub("2.1 End-to-end verifiability", "An end-to-end verifiable election aims to support three complementary checks. Cast-as-intended asks whether the encrypted ballot represents the voter's selection. Recorded-as-cast asks whether the accepted ballot appears unaltered in a public record. Tallied-as-recorded asks whether the result follows from the recorded ballots. These checks distribute trust: rather than requiring observers to accept a server's assertion, the protocol publishes evidence that can be independently recomputed. Helios is a key example of web-based open-audit voting and explicitly targets lower-coercion settings such as student elections [2].")
sub("2.2 Anonymous credentials", "Eligibility and secrecy create a design tension. A registration authority must know which person is eligible, but the ballot box should not know that person's identity. RSA blind signatures let a client obtain a signature on a message hidden from the signer. After unblinding, the ballot box can verify that the credential was authorised without receiving the original identity. D-Voting follows RSABSSA as documented in RFC 9474 [3]. The protocol does not conceal network timing or prevent a dishonest registration authority from manufacturing eligible identities; these are separate operational issues.")
sub("2.3 Public records and Merkle proofs", "A public bulletin board is a shared record against which voters and observers can check inclusion. Hash chains expose changes to prior blocks, while a Merkle tree proves that a particular ballot is included under a committed root. The Merkle proof concept parallels append-only transparency logs such as RFC 6962 [4]. These data structures support detection only if observers obtain and compare the authentic head of the record. A server that can show different views to isolated observers creates an equivocation problem, so independent validators and external publication matter.")
sub("2.4 Threshold cryptography", "A single decryption key holder can expose votes or release a premature count. Threshold techniques divide authority among trustees. The project uses distributed key generation so the election secret key is not assembled in one place, then combines a threshold of valid partial decryptions of the aggregate. This reduces unilateral control but shifts trust to the selection and independence of trustees. If enough trustees collude, they may decrypt individual ciphertexts outside the intended workflow.")
sub("2.5 Why a blockchain is insufficient", "A ledger can make an accepted record difficult to alter silently, but it cannot determine whether the voter device displayed the correct candidate, whether a person on the electoral roll exists, or whether coercion took place. Park and colleagues analyse these broader failure modes for Internet and blockchain voting [1]. D-Voting accordingly treats its permissioned blockchain as an audit and replication mechanism. Secrecy and ballot validity arise from cryptography, and legitimacy also depends on governance, deployment and public scrutiny.")

chapter(3, "Problem Definition and Objectives", "The project addresses the challenge of conducting a small, remotely accessible election while giving each participant a defined, checkable role. A successful prototype must show an entire election flow rather than only encryption or a ledger in isolation.")
sub("3.1 Problem statement", "A conventional centralised web voting system usually knows both the authenticated person and the selected option, and it can update a mutable database before reporting a result. External observers have limited means to distinguish honest operation from omission, duplicate voting or incorrect counting. Conversely, simply storing plaintext or encrypted votes on a blockchain does not establish eligibility, intention or privacy. The design problem is to compose eligibility, anonymous casting, ballot validity, publication and verifiable counting into one workflow with explicit trust boundaries.")
sub("3.2 Project objectives", "The central objective is to implement a coherent, demonstrable end-to-end verifiable workflow. Supporting objectives are to separate voter identity from cast ballots; reject malformed, replayed or unauthorised submissions; let voters check recorded inclusion; require a threshold of trustees for tally release; and allow public recomputation of the final count. The system should also make election administration visible and irreversible at key transitions, while exposing practical limitations rather than claiming universal security.")
table(["Objective", "Implemented approach", "Evidence to examine"], [
 ("Eligible participation", "Electoral roll and one blind-signed credential per entry", "Registration tests and issue route"),
 ("Ballot secrecy", "Browser-side ElGamal and separated services", "Crypto code and API payloads"),
 ("Valid ballots", "Disjunctive zero-knowledge proofs", "Ballot proof tests"),
 ("Recorded-as-cast", "Merkle proof and signed ledger head", "Verification portal and ledger tests"),
 ("Count integrity", "Homomorphic tally and threshold proofs", "Ceremony and recount tests"),
 ("Visible lifecycle", "Configuration/open/close records on chain", "Lifecycle tests")])
caption("Table 3.1  Objectives and corresponding mechanisms")
sub("3.3 Delimitations", "The prototype supports additive contests: a voter may select within configured limits and the encrypted selections can be summed. It does not implement ranked-choice counting, write-in ballots or a mixnet. It is not a replacement for electoral law, identity proofing, independent device assurance or physical election procedures. The architecture is best interpreted as a research and teaching system for a controlled election context.")

chapter(4, "Requirements and Threat Model", "Requirements are grouped by the user-facing election workflow and by cross-cutting assurances. The threat model is deliberately broader than a malicious database administrator: participants may act dishonestly, devices may be compromised and operational metadata may leak.")
sub("4.1 Functional requirements", "An administrator needs to configure candidates and selection limits, manage and freeze the roll, set a schedule, open and close polling, and observe the state of the system. A voter needs an understandable path from eligibility to credential acquisition, ballot selection, cast-or-audit choice, casting and tracking-code receipt. An observer needs access to the public election definition, ledger, inclusion proof and result. Trustees need a separate console in which they independently inspect the bulletin board before submitting a decryption share.")
table(["Category", "Requirement", "Primary component"], [
 ("Functional", "Issue at most one credential for each verified roll entry", "Registration authority"),
 ("Functional", "Encrypt and prove ballot validity before submission", "Browser and crypto package"),
 ("Functional", "Reject invalid or duplicate credential use according to re-vote rules", "Ballot box"),
 ("Functional", "Publish blocks and inclusion proofs", "Ledger and bulletin board"),
 ("Functional", "Close voting before a tally ceremony", "Lifecycle and trustees"),
 ("Non-functional", "Keep choice and encryption randomness out of server requests", "Browser"),
 ("Non-functional", "Allow independent verification and recovery after restart", "Validators and durable chain"),
 ("Non-functional", "Provide readable, responsive interaction and clear status", "Web interface")])
caption("Table 4.1  Functional and non-functional requirements")
sub("4.2 Assets and adversaries", "Important assets include the electoral roll, voter identity secrets, anonymous credential, vote choice, ballot encryption randomness, trustee shares, validator signing keys and the authenticated public record. An external attacker may send invalid requests or attempt denial of service. An insider may try to alter the roll or server software. A coercer may watch a voter and request evidence of a vote. A malicious browser, extension or served script may change the choice before encryption. A set of colluding trustees may attempt premature or individual decryption. No single cryptographic control addresses all of these adversaries.")
sub("4.3 Trust assumptions", "The design assumes clients receive a consistent election descriptor and issuer key, that fewer than the threshold number of trustees collude, and that enough validator authorities refuse invalid blocks. The electoral roll must be governed honestly and independently inspected before freeze. Browser-side secrecy assumes the client device and delivered JavaScript are not fully malicious. Transport security, trustworthy deployment of services and secure key storage are necessary operational assumptions; they are not established by local tests.")
sub("4.4 Security properties and exclusions", "The implemented protocol attempts to provide eligibility checking, ballot confidentiality before tally, ballot well-formedness, tamper-evident recording and publicly checkable tally evidence. It does not guarantee universal coercion resistance, protect against all endpoint malware, or authenticate real-world persons without an external process. Re-voting offers a limited opportunity to replace a coerced ballot but does not hide the fact that a replacement occurred. A precise security evaluation must report both achieved mechanisms and these exclusions.")

chapter(5, "System Architecture", "The architecture separates identity, casting, agreement and decryption into services that hold different secrets. This separation is a core security decision: a single routine should not have access to the voter identity, plaintext vote and power to rewrite the public record.")
sub("5.1 Logical components", "The cryptographic package is shared by the browser and server-side verifiers. The registration authority maintains eligibility and issues blinded credentials. The ballot box checks signed credentials and validity proofs, offers the public API and coordinates election administration. Validators maintain their own replicas of the ledger and attest only to blocks they independently verify. Trustees each hold a key share and participate in the final tally ceremony. The browser performs blinding, encryption and independent verification.")
table(["Component", "Receives", "Holds or publishes", "Must not learn"], [
 ("Registration authority", "Identity and blinded message", "Electoral roll, issuer private key", "Credential message and vote"),
 ("Voter browser", "Public election data", "Choice and temporary secrets in memory", "Other voters' choices"),
 ("Ballot box", "Credential, encrypted ballot, proofs", "Public bulletin board", "Voter identity and plaintext choice"),
 ("Validator", "Proposed blocks", "Own signing key and chain replica", "Plaintext choice"),
 ("Trustee", "Public chain and encrypted totals", "One decryption share", "Voter identity")])
caption("Table 5.1  Service responsibilities")
sub("5.2 Deployment view", "The local development command starts four validator processes, five trustee processes, the registration service and the ballot box. The services communicate over HTTP in the development arrangement, while the browser accesses the web application. Each validator has its own key and replica rather than being a simulated object inside the ballot-box process. The trustee console is served by the trustee process. In production, these parties would need truly separate operators, hosts, networks and key-management procedures; multiple local processes alone do not produce organisational independence.")
table(["Voter", "Registration", "Ballot box", "Validators", "Trustees"], [
 ("Prove eligibility →", "Check roll", "", "", ""),
 ("Blind credential ↔", "Sign blind input", "", "", ""),
 ("Encrypt and cast →", "", "Verify and propose →", "Verify, sign, store", ""),
 ("Check inclusion ←", "", "Serve proof ←", "Committed head", ""),
 ("", "", "Aggregate totals →", "Public chain", "Verify and decrypt shares"),
 ("Check result ←", "", "Publish result", "Verify", "Threshold proof")])
caption("Figure 5.1  Separation of project parties and data flow")
sub("5.3 Repository organisation", "The monorepo has packages/crypto for group operations, blind signatures, zero-knowledge proofs, ballot construction and threshold protocols; packages/ledger for canonical encoding, block validation, Merkle proofs and node replication; services/registration for roll and credential APIs; services/ballot-box for the election, board and portal; services/validator for independent validation; and services/trustee for share custody and ceremony participation. Tests are colocated with each workspace. Repository documentation records design rationale and known limitations.")
sub("5.4 Data boundaries", "The browser retains the selected candidate indices, blinding factor and encryption randomness only in local runtime memory during a cast. The registration authority receives identity material and a blinded message, but not an unblinded credential. The ballot box receives the credential and encrypted ballot, but not a civil identity. The chain intentionally publishes encrypted ballots and audit data. While this division is strong at the protocol level, network addresses, timing and compromised frontend code may still correlate actions. Those environmental boundaries need their own safeguards.")

chapter(6, "Cryptographic Protocol", "D-Voting combines several established primitives. The report focuses on what each primitive proves, which key is required, and what remains outside its protection. Mathematical notation is simplified to make the design readable without implying a formal proof of the entire implementation.")
sub("6.1 Election group and public key", "Ballot encryption uses a prime-order subgroup of a finite field. Let p be the field prime, q the subgroup order, g a generator, x a secret exponent and y = g^x mod p the public key. The group parameters are based on RFC 3526 MODP groups [5]. The project supports parameter sizes used in its tests and benchmarks, including a 3072-bit configuration. Correct parameter and subgroup validation matters because malformed group elements can undermine secrecy or validity proofs.")
sub("6.2 Blind-signature credential", "The client encodes a random credential message, blinds it and asks the registration authority to sign the blinded value after eligibility checks. The authority records that the roll entry has been served once, while a database uniqueness constraint and transaction logic defend against concurrent double issuance. The client unblinds and verifies the RSA-PSS-based signature. At cast time, the ballot box verifies the signature and a credential-derived fingerprint used to apply the re-voting rule. The blind-signature specification is RFC 9474 [3]; it is not a general solution to timing correlation or a dishonest roll.")
sub("6.3 Exponential ElGamal ballot", "For a binary choice m ∈ {0,1}, a simplified exponential ElGamal ciphertext is (A,B) = (g^r, y^r g^m), where r is fresh randomness. Multiplying ciphertexts componentwise adds their plaintext exponents. Thus all accepted ballot ciphertexts for one candidate can be combined without decrypting any individual ballot. After the threshold decryption removes the encryption factor, the tally is recovered as a small discrete logarithm over the allowed count range. This is why the protocol suits additive elections but not arbitrary ranked ballots.")
sub("6.4 Ballot validity proofs", "Encryption alone would permit a voter to submit an out-of-range value that distorts the count. Disjunctive Chaum–Pedersen proofs show that each ciphertext encrypts one of the permitted values without revealing which one. A separate selection-limit proof ensures the total number of selected candidates conforms to the election definition. Fiat–Shamir challenges bind proof transcripts to the election and ballot context. These proofs establish mathematical well-formedness; they do not establish that the browser used the choice the voter intended.")
table(["Mechanism", "Purpose", "Important limitation"], [
 ("RSABSSA blind signature", "Eligibility without ballot-to-identity content link", "Timing and roll honesty remain"),
 ("Exponential ElGamal", "Encrypted additive tally", "Only additive contest forms"),
 ("Zero-knowledge validity proof", "Reject malformed or inflated vote", "Cannot prove human intent"),
 ("Benaloh cast-or-audit", "Probabilistic client correctness check", "Needs trustworthy independent audit"),
 ("Threshold decryption", "No unilateral tally release", "Threshold collusion can decrypt"),
 ("Ed25519 validator signatures", "Authenticate block attestations", "Authority key custody matters")])
caption("Table 6.1  Cryptographic mechanisms and their role")
sub("6.5 Cast-or-audit challenge", "A malicious client can display candidate A while encrypting candidate B and still produce a valid proof. The Benaloh challenge addresses this gap by letting the voter decide whether a prepared ballot is cast or spoiled and opened for inspection. An audited ballot reveals its randomness so the client can check the encryption against the intended selection; it is never counted. A malicious client that cannot predict which prepared ballots will be audited risks detection. This is probabilistic and depends on a genuinely independent check of the audited data.")
sub("6.6 Distributed key generation", "The election key is formed by a Pedersen distributed key generation ceremony among trustees. Each trustee contributes secret polynomial shares and public commitments; valid contributions combine into one election public key while each participant retains only its own share. The key is not assembled on the ballot-box server. DKG removes a single trusted dealer from the main election path, but it does not remove the need to verify trustee identities, channels and key custody.")
sub("6.7 Threshold tally release", "After the election closes, a trustee downloads the board, checks validator signatures and recomputes the aggregate before applying its share. It submits a partial decryption with a proof linking that output to its public share. When a threshold—three of five in the development configuration—of valid shares is available, the service combines them and publishes the result and evidence. The public can independently aggregate ballots and verify the shares. Individual encrypted ballots should not be passed to the decryption ceremony.")
table(["Step", "Voter browser", "Other party"], [
 ("1", "Fetch and pin election information", "Registration and board publish keys"),
 ("2", "Blind a random credential", "Registration checks roll and signs blind input"),
 ("3", "Unblind and verify signature", "No party learns the credential link"),
 ("4", "Encrypt selections and create proofs", "Ballot box checks proof and credential"),
 ("5", "Cast or audit the prepared ballot", "Ledger records cast or spoiled event"),
 ("6", "Check tracking code and inclusion", "Validators attest to committed block")])
caption("Figure 6.1  Credential and ballot protocol sequence")

chapter(7, "Ledger and Public Bulletin Board", "The permissioned ledger is designed to make election events and accepted ballots tamper-evident and publicly auditable. It is not used to store plaintext votes or to replace the cryptographic checks around a ballot.")
sub("7.1 Block structure and canonical encoding", "Each block links to its predecessor by hash and commits to its contents. The ledger package encodes the hashable data in a canonical binary format rather than relying on potentially ambiguous JSON serialisation. Block headers and Merkle roots provide compact commitments to the ballot records. A verifier must recompute the expected hashes and reject a mismatch; displaying a server-supplied 'valid' label is not enough.")
sub("7.2 Permissioned Proof-of-Authority", "Validator authorities maintain independent replicas and possess separate Ed25519 signing keys, whose algorithm is specified in RFC 8032 [6]. A proposed block is checked by each authority against chain rules and ballot validity before attestation. A Byzantine supermajority quorum is required to seal it. The repository also includes proposer failover and resynchronisation of lagging nodes. These features improve the demonstrable integrity of the local system, but real independence requires separate governance and secure operation of validator machines.")
sub("7.3 Merkle inclusion and tracking", "Accepted ballot records are leaves of a Merkle tree. A tracking code lets a voter locate the corresponding public record, and a Merkle path lets the browser recompute the block root from that leaf. The verification portal checks the block hash, validator signatures and Merkle path on the client side. This gives evidence of recorded-as-cast under the authentic chain head. It does not disclose how the voter selected, and a voter should not treat the tracking code as a receipt proving vote content.")
table(["Published item", "Independent check", "Question answered"], [
 ("Election descriptor", "Compare configuration with opening block", "What rules and keys governed the poll?"),
 ("Ledger blocks", "Recompute hashes and validator quorum", "Was the record changed?"),
 ("Merkle path", "Recompute root from ballot leaf", "Was this ballot included?"),
 ("Encrypted ballots", "Recheck proofs and aggregate", "Are records valid and counted?"),
 ("Trustee shares and proofs", "Verify each share and result", "Does the tally follow from the record?")])
caption("Table 7.1  Public verification artefacts")
sub("7.4 Re-voting and last-ballot rule", "A credential may be used again to replace a prior choice under the election's re-voting rule. The ballot box retains credential fingerprints, and the tally selects the latest valid ballot for each credential. This provides a limited response to coercion or a mistaken cast. It also means the public board can reveal that the same anonymous credential voted again. A coercer can observe the existence of a later ballot even without learning its content; re-voting should therefore be described as mitigation rather than full coercion resistance.")
sub("7.5 Durable publication and remaining risk", "Ledger files are written durably and validators can recover a lagging replica. The opening and closing transitions are chain records so a restart cannot simply revert the application to an earlier phase. Nevertheless, public verification relies on observers obtaining a consistent chain head. Independent mirroring, downloadable snapshots, cross-checking among observers and an externally hosted verifier would improve resistance to a server showing selective or inconsistent views.")

chapter(8, "Election Lifecycle and User Experience", "A secure design must also be understandable to the people using it. The application separates administrative, voter, trustee and observer tasks into distinct views, while the election itself follows one-way state changes that are committed to the ledger.")
sub("8.1 Lifecycle states", "Before opening, the commission composes candidates, choice limits and schedule, enrols voters and freezes the roll. Opening commits the final election definition, public keys, trustee roster, validator set and roll commitment to the first block. During polling, the ballot box accepts valid ballots but does not publish a running result. Closing is an irreversible chain event. Only then do trustees verify the record and contribute partial decryptions. The published result can be checked against the chain and proofs.")
table(["Setup", "Open", "Closed", "Tallied"], [
 ("Edit and freeze configuration", "Accept and audit ballots", "Reject new ballots", "Publish result and proof"),
 ("No public votes yet", "No running tally", "Trustees may contribute", "Observers recount")])
caption("Figure 8.1  Election lifecycle state progression")
sub("8.2 Voter journey", "The voter page explains the current phase and guides the user through eligibility, credential issuance, choice, review and ballot preparation. The cast-or-audit choice is presented before the ballot is finally submitted. After a successful cast, the tracking code provides a path to the verification page. The interface should make the difference between 'prepared', 'cast', 'audited' and 'verified' unmistakable: an audited ballot is deliberately spoiled and never counted, while a prepared ballot is not a recorded vote.")
sub("8.3 Observer and results journey", "The verification view accepts a tracking code and performs checks in the browser. The chain view exposes block-level evidence and election events. The results view shows the published tally and the trustee ceremony state; it should not display totals during live voting. This division allows an observer to move from a high-level result to the cryptographic evidence without requiring administrative access. Clear labels and explanations are essential because a 'verified' badge can otherwise imply a broader guarantee than the particular check supports.")
table(["Page", "Primary user", "Core task"], [
 ("/vote", "Voter", "Register, choose, prepare, audit or cast"),
 ("/verify", "Voter or observer", "Check code, signatures and Merkle inclusion"),
 ("/results", "Public", "Read result and recount evidence"),
 ("/chain", "Public", "Inspect blocks and lifecycle entries"),
 ("/admin", "Commission", "Configure, freeze, open and close"),
 ("Trustee console", "Trustee", "Verify board and contribute a share")])
caption("Table 8.1  Interface pages and primary tasks")
sub("8.4 Interface design considerations", "The current frontend uses responsive layouts, strong typographic hierarchy, election status cues, compact explanatory copy and a visual hero asset. These choices can increase clarity but must never hide critical information behind decoration. Colour should supplement, not replace, text status; controls need visible focus states, sufficient contrast and usable labels. WCAG 2.2 provides a useful reference for accessibility review [7]. An academic evaluation should include keyboard and screen-reader testing before claiming accessibility compliance.")
sub("8.5 Error and trust communication", "The system should distinguish a network problem from an invalid credential or a ballot-proof rejection. The user needs a way to safely retry without assuming that a failed page response means a vote was not recorded. After casting, the safest instruction is to verify inclusion with the tracking code. Cryptographic claims should be phrased narrowly: for example, a valid Merkle path proves inclusion under a specific signed block root, not that the registration roll was fair or that the client was free from malware.")

chapter(9, "Implementation and Data Flow", "The project is implemented in TypeScript, using Node's native TypeScript execution in the required runtime. The source is organised into reusable packages and narrow services so protocol logic can be tested without relying on the web interface.")
sub("9.1 Technology stack", "The root package specifies Node.js version 22.18 or later. TypeScript is typechecked through workspace scripts; the runtime strips types without a separate transpilation step for server source. The crypto package uses WebCrypto and native BigInt rather than third-party cryptographic packages. HTTP services use Hono. The registration repository supports PostgreSQL and an in-memory mode for demonstration and tests. The browser crypto bundle is produced with the build:web script, while the static frontend is served by the ballot-box service.")
sub("9.2 Registration data flow", "A roll entry is enrolled with an out-of-band code. The registration service stores derived values rather than the raw voter secret, and the roll can be frozen and exported for scrutiny. During registration it authenticates the voter, issues a short-lived token and signs one blinded credential message. The signing operation is tied to transaction logic to prevent duplicate issuance or loss of entitlement on a signing failure. The resulting anonymous credential remains with the voter browser and is later presented to the ballot box, not to the registration service.")
sub("9.3 Casting data flow", "The browser retrieves the election descriptor and uses its public key to encrypt one value for each candidate. It attaches validity proofs and an anonymous credential. The ballot box checks the election is open, verifies the credential and proof, applies re-voting rules, and submits an accepted record to validators. The proposer cannot create a valid sealed block alone because validators re-check the proposed content and attest with their own keys. The response includes a tracking code for public inclusion checking.")
sub("9.4 Closing and tally data flow", "Closing creates an immutable lifecycle entry. The ballot-box ceremony calculates encrypted totals from the latest accepted ballot per credential. Each trustee independently verifies the ledger and recomputes that aggregate before sending a partial decryption with proof. The ballot box accepts a threshold of valid shares and publishes the final count and proof material. A public verifier can derive the same encrypted totals from the board and check that the decrypted tally corresponds to those totals.")
sub("9.5 Persistence and restart behaviour", "The ledger is durable and is reloaded for validation after a restart. Election definition and closure are part of that record, making those lifecycle decisions persistent. Some operational state is not equally durable: the repository notes that a bounded operator audit log and in-progress ceremony state are in memory. A restart during tally may therefore require trustees to resubmit shares. These details matter for realistic deployment planning, even though they do not erase the chain record.")

chapter(10, "Verification and Testing", "The project includes tests across the cryptographic, ledger and service workspaces. Testing is evidence that selected cases behave as intended, not a proof that the entire election or deployment is secure. This chapter separates observed local results from claims that would require independent assessment.")
sub("10.1 Test organisation", "Crypto tests cover blind signatures, ElGamal properties, zero-knowledge proofs, threshold operations, distributed key generation and the Benaloh challenge. Ledger tests address canonical encoding, block validation, Merkle paths, file storage and node behaviour. Service tests cover registration and roll administration, ballot-box validation, lifecycle transitions, tally publication, trustee operation and HTTP consensus. The presence of tests for a property indicates intentional coverage; their exact assertions should be inspected when making a stronger claim.")
sub("10.2 Local verification result", "A full test run was observed to pass 516 of 516 tests during preparation of this report. The repository README still mentions an earlier count of 495; this report uses the observed run rather than the stale documentation figure. Typechecking was also observed to pass for the ballot-box and trustee workspaces. This is a point-in-time result, not a continuous-integration guarantee, and it does not imply penetration testing, accessibility certification or independent cryptographic audit.")
table(["Evidence", "Observed or available result", "Interpretation"], [
 ("Workspace test suite", "516/516 tests passed in observed run", "Regression checks succeeded at that revision"),
 ("Typechecking", "Ballot-box and trustee workspaces passed", "Selected source types were consistent"),
 ("Crypto test files", "Blind RSA, ZKP, ElGamal, DKG, threshold", "Core protocol has unit-level coverage"),
 ("Ledger test files", "Chain, Merkle, node and file store", "Record validation has focused coverage"),
 ("Service test files", "Registration, ballot-box, trustee, validator", "API and lifecycle scenarios are exercised"),
 ("Full-election demo", "Script supplied in repository", "Reproducible walkthrough; not a field trial")])
caption("Table 10.1  Test and verification evidence")
sub("10.3 Negative tests and attack cases", "The test tree includes cases intended to reject invalid ballot proofs, replay or cloned ballots, unauthorised or duplicate credential issuance, malformed ledger data and incorrect ceremony contributions. The demonstration script also narrates attacks such as a malicious voting client detected by audit and a tampered ledger detected during verification. These cases are useful for a viva because they show what a control rejects, not merely the happy path. They should be rerun on the submission machine and their actual outputs captured if the college expects screenshots.")
sub("10.4 Performance evidence", "The README reports indicative timings for a 3072-bit, four-candidate configuration: approximately 485 ms to create a ballot, 730 ms to verify one, 98 ms for a partial decryption and under 1 ms to homomorphically combine ten ballots. These numbers are repository-reported, not independently benchmarked for this report. They depend on hardware, runtime, parameters and workload. A future evaluation should document the machine, repeated samples, percentile latency, memory use and throughput under concurrent voters.")
sub("10.5 Evaluation criteria", "A useful evaluation matrix should include end-to-end flow completion, correct rejection of invalid inputs, browser verification against a known chain head, restart recovery, trustee refusal when the board is inconsistent, accessible interaction and load behaviour. The prototype has strong automated coverage of protocol paths, but operational exercises with separate machines and people would be necessary to evaluate deployment assumptions. Security testing should include frontend supply-chain integrity, network transport and key compromise scenarios.")

chapter(11, "Security Discussion", "The project is strongest when its claims are read as conditional, checkable protocol properties. It separates powers and publishes evidence, but neither the ledger nor cryptography can make an untrusted person, device or institution honest.")
sub("11.1 Privacy and unlinkability", "The registration authority sees a verified identity and a blinded message; the ballot box sees an unblinded credential and encrypted vote. This blocks a direct content link between the two service records when the blind-signature protocol is used correctly. However, simultaneous observation of network metadata or near-adjacent registration and cast times can support correlation. A client that loads malicious JavaScript may also disclose the choice before encryption. A stronger deployment would separate the issuance period from voting and provide independent verification of client code.")
sub("11.2 Integrity and verifiability", "Zero-knowledge proofs allow the ballot box and validators to reject mathematically invalid ballots, signed blocks make the public record hard to rewrite without a quorum, and Merkle proofs support inclusion checks. Threshold proofs make the final tally checkable. The guarantees are conditional on authentic public keys and chain heads. If the same operator can silently replace all keys in a private deployment or prevent observers from comparing views, the public evidence loses much of its value. Publishing immutable fingerprints through multiple independent channels would improve this boundary.")
table(["Threat", "Current control", "Residual risk"], [
 ("Invented voter on roll", "Freeze, commitment and publication", "Fraud before freeze needs human audit"),
 ("Malicious voter client", "Cast-or-audit challenge", "Audit device may share compromise"),
 ("Ballot-box tampering", "Validator quorum and public verification", "Colluding authorities or withheld views"),
 ("Trustee misuse", "3-of-5 shares and proofs", "Three colluding trustees can decrypt"),
 ("Coercion", "Last-valid-ballot re-voting", "Later vote remains observable"),
 ("Traffic correlation", "Content unlinkability", "Timing and IP metadata remain"),
 ("Service compromise", "Role separation and checks", "Key theft and malicious frontend remain")])
caption("Table 11.1  Threats and residual risk")
sub("11.3 Eligibility and governance", "A cryptographic credential proves that the registration authority authorised a ballot; it does not prove that the underlying electoral-roll entry corresponds to a real eligible person. A fabricated entry created before roll freeze can receive a valid credential and ballot. The roll commitment exposes later alterations but cannot validate the original list. Independent roll review, objection windows, named administrators and dual approval for sensitive actions are governance requirements, not optional cosmetic features.")
sub("11.4 Coercion and small-election privacy", "Re-voting can help a voter replace an earlier coerced vote when they later have privacy, but the public credential fingerprint makes replacement visible. Furthermore, decrypting an aggregate containing a single vote discloses that vote, regardless of the strength of encryption. Small elections need a minimum tally-size policy and careful handling of uncontested or tiny races. A claim of coercion resistance would require a different protocol and explicit analysis of receipts, devices and physical observation.")
sub("11.5 Deployment security", "The repository itself flags missing production controls including TLS 1.3 termination, mutual authentication among services, real-world identity proofing and KMS or HSM-backed signing. The admin console uses a bearer token, and operational logs are in memory. These choices are acceptable to disclose in a prototype but not to ignore in a binding election. A production threat assessment would include backups, key rotation, patching, incident response, independent monitoring, accessibility and legal compliance.")

chapter(12, "Limitations and Future Work", "The future-work agenda follows directly from the threats the current design does not close. Improvements should be evaluated for their effect on both security and usability rather than added merely to increase technical complexity.")
sub("12.1 Identity and roll assurance", "A first priority is an independently governed electoral roll. The project already freezes, commits and can publish identifiers, but it cannot detect an invented entry before freeze. Future deployment should include a verified source of eligibility, review and objection procedures, reconciled issuance counts and dual authorisation for additions or revocations. Personal data should be minimised and access logged in durable, write-once records.")
sub("12.2 Operator and key governance", "Administrative actions should require named accounts, role-based permissions, multifactor authentication and two-person approval for opening, closing and roll modifications. Validator and trustee keys should be generated and held by independent organisations, preferably with HSM-backed operations. A transparent key ceremony, witnessed fingerprints, secure backup and recovery plans would make the cryptographic separation credible outside a single development machine.")
sub("12.3 Independent client and verifier", "The browser application is delivered by an operator-controlled service. Even though the source and bundle checksum are visible, a voter may unknowingly run altered code. The project would benefit from reproducible builds, signed releases, subresource integrity, an independently hosted verifier and a standalone verifier command-line tool that reads exported board data. An independently maintained mobile or desktop verifier would help separate the audit path from the voting frontend.")
sub("12.4 Availability and scalability", "A realistic evaluation should use concurrent load, slow networks, service restarts and validator failure. The current proof verification cost is relevant to peak casting throughput, and rate limiting must avoid excluding legitimate voters. Distributed rate limiting, queue monitoring, durable ceremony state, operational dashboards and tested disaster recovery are needed. Published benchmarks should use documented hardware and repeatable workloads rather than one illustrative run.")
sub("12.5 Accessibility and public comprehension", "Formal accessibility testing should cover keyboard-only operation, screen readers, responsive zoom, contrast, error recovery and plain-language explanations of audit versus cast. Usability studies should determine whether voters understand that an audited ballot is spoiled, how to retain a tracking code safely and what verification actually proves. A technically correct system can still fail if people misinterpret its states or cannot use it reliably.")
sub("12.6 Broader electoral properties", "Ranked-choice and write-in contests would require verifiable mixing or a different tally protocol. Stronger coercion resistance would require substantially different credential and receipt mechanisms. Research should also address metadata correlation, independent observation of chain heads, minimum tally sizes and voter-device compromise. These are research directions rather than features that can be promised by changing the user interface alone.")

chapter(13, "Conclusion", "D-Voting demonstrates an end-to-end electronic voting workflow in which eligibility, secrecy, recording and counting are separated across identifiable roles. The browser blinds the credential and encrypts the vote; the registration authority confirms eligibility without seeing the final credential; the ballot box checks cryptographic evidence; validators make the record tamper-evident; and trustees jointly release a verifiable aggregate. The public interface offers a way to inspect inclusion and the final tally.")
body("The most important design conclusion is that the blockchain is only an audit layer. It strengthens publication and replication, while secrecy depends on encryption and separation of knowledge, and legitimacy depends on an honest roll and independent governance. The observed automated test run passed 516 tests, providing useful regression evidence for the prototype. It does not prove production safety. The explicit limitations—coercion, client compromise, timing correlation, trustee collusion and missing operational controls—should guide any next phase.")
body("As an academic project, the system offers a concrete setting for studying how cryptographic protocols, distributed systems, backend services and usable interfaces interact. A successful next stage would pair protocol hardening with independent operational oversight and human-centred evaluation. Until that work is complete, the system should be presented as a research and demonstration prototype for controlled settings, not as a ready-to-deploy public-election platform.")

page(); heading("References", 1)
refs = [
"[1] S. Park, M. Specter, N. Narula and R. L. Rivest, ‘Going from bad to worse: from Internet voting to blockchain voting,’ Journal of Cybersecurity, vol. 7, no. 1, tyaa025, 2021. https://academic.oup.com/cybersecurity/article/7/1/tyaa025/6137886",
"[2] B. Adida, ‘Helios: Web-based Open-Audit Voting,’ Proceedings of the 17th USENIX Security Symposium, 2008. https://www.usenix.org/conference/17th-usenix-security-symposium/helios-web-based-open-audit-voting",
"[3] F. Denis, K. Jacobs and C. A. Wood, ‘RSA Blind Signatures,’ RFC 9474, October 2023. https://www.rfc-editor.org/rfc/rfc9474.html",
"[4] B. Laurie, A. Langley and E. Kasper, ‘Certificate Transparency,’ RFC 6962, June 2013. https://www.rfc-editor.org/rfc/rfc6962.html",
"[5] T. Kivinen and M. Kojo, ‘More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE),’ RFC 3526, May 2003. https://www.rfc-editor.org/rfc/rfc3526.html",
"[6] S. Josefsson and I. Liusvaara, ‘Edwards-Curve Digital Signature Algorithm (EdDSA),’ RFC 8032, January 2017. https://www.rfc-editor.org/rfc/rfc8032.html",
"[7] W3C, ‘Web Content Accessibility Guidelines (WCAG) 2.2,’ W3C Recommendation, 2023. https://www.w3.org/TR/WCAG22/",
"[8] D-Voting repository, README.md; docs/registration-and-blind-signatures.md; docs/ballot-encryption-and-tallying.md; docs/ledger-and-bulletin-board.md; docs/election-lifecycle-and-administration.md; docs/cast-as-intended.md; docs/threshold-key-generation.md. Local source inspected September 2026."
]
for ref in refs: para(ref)

page(); heading("Appendix A  API Summary", 1)
body("The following table summarises representative routes visible in the project documentation. It is not an exhaustive API contract; request schemas and error codes should be read from the current source before integrating another client.")
table(["Service", "Method and route", "Purpose"], [
 ("Registration", "GET /v1/issuer", "Publish issuer key and key identifier"),
 ("Registration", "POST /v1/register", "Issue short-lived registration token"),
 ("Registration", "POST /v1/credential/issue", "Sign blinded credential"),
 ("Registration", "POST /v1/admin/roll", "Add electoral-roll entries"),
 ("Registration", "POST /v1/admin/roll/freeze", "Freeze and commit roll"),
 ("Ballot box", "GET /v1/election", "Publish election descriptor"),
 ("Ballot box", "POST /v1/ballots", "Submit cast ballot"),
 ("Ballot box", "POST /v1/ballots/audit", "Spoil and disclose audit ballot"),
 ("Ballot box", "GET /v1/bulletin/*", "Read blocks, proof and result"),
 ("Ballot box", "GET /v1/ceremony", "Observe tally ceremony"),
 ("Ballot box", "POST /v1/ceremony/shares", "Submit trustee contribution"),
 ("Ballot box", "POST /v1/admin/election/open", "Commit and open election"),
 ("Ballot box", "POST /v1/admin/election/close", "Close election")])
caption("Table A.1  Representative HTTP endpoints")
body("Administrative endpoints require appropriate credentials. The exact route behaviour, payload shape, state preconditions and security policy are defined by the service implementation and tests. The public bulletin routes should remain available to observers even when write paths are rate limited.")

page(); heading("Appendix B  Setup and Demonstration", 1)
body("The repository requires Node.js 22.18 or later. For a local demonstration, install workspace dependencies, build the browser crypto bundle, run automated tests and start the development stack. The full RUNNING.md file contains current step-by-step instructions and environment details. The commands below are for a development environment, not a secure election deployment.")
table(["Command", "Purpose"], [
 ("npm install", "Install workspace dependencies"),
 ("npm run build:web", "Build browser cryptography bundle"),
 ("npm test", "Run workspace tests"),
 ("npm run typecheck", "Typecheck workspaces"),
 ("npm run dev", "Start local services and web interface"),
 ("npm run demo", "Run narrated full-election demo")])
sub("B.1 Suggested viva sequence", "Show the admin console before opening and explain the roll freeze. Open the election and identify the definition committed in block 0. Register one demonstration voter, prepare a ballot and use the cast-or-audit option to explain intent checking. Cast a separate ballot and copy its tracking code. Open the verification page to inspect the Merkle path and validator signatures. Close the poll, show trustee participation and finally explain how the public result is recomputed. A second pass can demonstrate rejection of an invalid ballot or tampered block.")
sub("B.2 Submission checklist", "Replace every bracketed cover-page and certificate placeholder. Personalise the acknowledgements and declaration; sign only after confirming their truth. Confirm the exact repository revision, repeat the test run on the submission machine, and update Chapter 10 if results differ. Verify page numbering and any institution-prescribed margin or citation format. If screenshots or output logs are required, capture them from the actual running system with dates and explanatory captions.")

page(); heading("Appendix C  Glossary", 1)
table(["Term", "Meaning in this report"], [
 ("Ballot box", "Service that validates and records encrypted ballots"),
 ("Blind signature", "Signature obtained without the signer seeing the final message"),
 ("Bulletin board", "Public election record and verification data"),
 ("Cast-or-audit", "Choice between recording a prepared ballot or opening it for a check"),
 ("Credential", "Anonymous token proving registration authority approval"),
 ("DKG", "Distributed key generation among trustees"),
 ("ElGamal", "Public-key encryption scheme used for additive aggregation"),
 ("End-to-end verifiability", "Ability to check intention, inclusion and tally evidence"),
 ("Merkle proof", "Compact proof that a record is under a published tree root"),
 ("PoA", "Proof-of-Authority agreement among known validators"),
 ("Threshold decryption", "Decryption requiring a defined number of trustees"),
 ("Zero-knowledge proof", "Proof of validity without revealing the hidden choice")])
body("A valid proof should always be interpreted under its assumptions and authenticated public inputs. For example, an inclusion proof refers to a particular Merkle root; it is not evidence that the electoral roll was free of invented entries. This distinction is central to the project's security model.")

doc.core_properties.title = "D-Voting Project Report"
doc.core_properties.subject = "Academic report on an end-to-end verifiable electronic voting prototype"
doc.core_properties.keywords = "electronic voting, cryptography, blockchain audit, project report"
# Ask Word-compatible editors to refresh fields when the document opens.
settings = doc.settings.element
update = OxmlElement("w:updateFields")
update.set(qn("w:val"), "true")
settings.append(update)
doc.save(OUT)
print(OUT)
