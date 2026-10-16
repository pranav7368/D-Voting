/**
 * Voter-facing text in English and Hindi.
 *
 * Switching language re-renders text in place and never reloads: a reload
 * would destroy the voting credential, which lives only in this tab's memory.
 * The choice itself is not stored anywhere, for the same reason nothing else
 * on the voting page is.
 *
 * Elements opt in with data-i18n="key" (text) or data-i18n-placeholder="key".
 * Strings are plain text; nothing here is ever inserted as HTML.
 */

const STRINGS = {
  en: {
    "lang.switch": "हिंदी",
    "lang.switchLabel": "पेज हिंदी में देखें",
    "skip": "Skip to voting",
    "nav.vote": "Vote", "nav.verify": "Verify ballot", "nav.results": "Results", "nav.record": "Public record",
    "bar.loading": "Loading election…",
    "status.setup": "Not open yet", "status.scheduled": "Opens soon", "status.voting": "Voting is open",
    "status.closed": "Voting closed", "status.published": "Result published",
    "rule.exactly": "Choose exactly {n}", "rule.range": "Choose {min} to {max}", "rule.upTo": "Choose up to {n}",
    "closes": "Closes {when}",
    "rail.identify": "Identify", "rail.choose": "Choose", "rail.confirm": "Review", "rail.done": "Receipt",

    "id.title": "Confirm you can vote",
    "id.lede": "Enter the details printed on your polling card.",
    "id.roll": "Roll number", "id.rollHelp": "On your polling card, for example R-100001",
    "id.code": "Enrolment code", "id.codeHelp": "Dashes, spaces and capital letters do not matter",
    "id.codePh": "Enter your code",
    "id.go": "Continue to ballot", "id.busy": "Getting your anonymous voting pass…",
    "id.missing": "Enter both your roll number and enrolment code.",
    "id.keep": "Keep this tab open until you have cast your vote. Your voting pass exists only in this tab; reloading it will lose your place, and your polling card cannot be used again.",

    "ch.title": "Your ballot",
    "ch.lede": "Select your choice. It is locked (encrypted) on this device before anything is sent.",
    "ch.sheet": "Ballot paper",
    "ch.select": "Select", "ch.selected": "Selected",
    "ch.nota": "None of the Above",
    "ch.go": "Review my choice", "ch.busy": "Locking your choice on this device…",
    "ch.ruleOne": "Select exactly one option.",
    "ch.ruleExact": "Select exactly {n} options.",
    "ch.ruleRange": "Select between {min} and {max} options.",
    "ch.nothingSent": "Nothing has been sent yet.",

    "rv.title": "Check, then cast",
    "rv.lede": "This is the choice your device has locked. Make sure it is right.",
    "rv.yourChoice": "Your choice", "rv.noChoice": "No option selected",
    "rv.check": "Ballot check code", "rv.checkHelp": "A short code for this exact locked ballot. You can compare it on another device.",
    "rv.fullCode": "Show the full fingerprint",
    "rv.cast": "Cast my vote", "rv.casting": "Casting…",
    "rv.change": "Change my choice",
    "rv.auditTitle": "Not sure the app locked what you chose?",
    "rv.auditBody": "You can test this ballot instead of casting it. The app must then reveal how it locked your choice, so it can be checked. A tested ballot cannot be counted, so you will vote again afterwards.",
    "rv.audit": "Test this ballot instead", "rv.auditing": "Testing…",
    "rv.auditOk": "Test passed: this ballot really did contain your choice. It has now been used up for the test. Choose again to cast a fresh ballot.",
    "rv.auditBad": "WARNING: do not use this device. The test failed: {reason}",

    "dn.kicker": "Vote cast",
    "dn.title": "Your vote has been cast",
    "dn.lede": "Keep your tracking code. It proves your ballot is in the public record, without revealing how you voted.",
    "dn.code": "Tracking code",
    "dn.copy": "Copy", "dn.copied": "Copied.", "dn.copyFail": "Copy failed. Select the code and copy it by hand.",
    "dn.print": "Print or save receipt", "dn.verify": "Verify my ballot",
    "dn.t.received": "Received by the ballot box",
    "dn.t.receivedDetail": "Your encrypted ballot and its proofs were accepted.",
    "dn.t.sealed": "Sealed into the public record",
    "dn.t.sealedWait": "Waiting for the independent authorities to sign the next block…",
    "dn.t.sealedDetail": "Block {block}, signed by {sigs} of {total} independent authorities.",
    "dn.t.counted": "Counted in the published result",
    "dn.t.countedWait": "After voting closes, the trustees unlock the totals. Ballots are never opened one by one.",
    "dn.t.countedDetail": "The result is published with proofs anyone can recheck.",
    "dn.revoteSummary": "Need to replace this vote?",
    "dn.revoteBody": "If someone pressured you, you can vote again from this tab while it is open. Only your latest vote is counted.",
    "dn.revote": "Vote again",
    "dn.receiptTitle": "D-Voting receipt",
    "dn.receiptNote": "This receipt does not show how you voted. Check it at {url}",

    "kn.title": "Who knows what, right now",
    "kn.lede": "Each party learns only what it needs. No single one can link you to your vote.",
    "kn.device": "This device", "kn.ra": "Registration service", "kn.box": "Ballot box",
    "kn.validators": "Independent authorities", "kn.trustees": "Trustees",
    "kn.nothing": "Nothing about you yet",
    "kn.device.choose": "Your anonymous voting pass, in memory only",
    "kn.device.confirm": "Your choice, and the secret used to lock it",
    "kn.device.done": "Your tracking code. The lock secret has been destroyed",
    "kn.ra.after": "Your roll number, and that you received a pass. It signed the pass without seeing it, so it cannot recognise your ballot",
    "kn.ra.before": "Will see your roll number only",
    "kn.box.done": "A locked ballot from an anonymous pass. Not who you are, not your choice",
    "kn.box.before": "Nothing yet",
    "kn.val.done": "The locked ballot, which they check and seal. Never your choice",
    "kn.val.before": "Nothing yet",
    "kn.tr": "Nothing until voting closes. Then {k} of {n} together unlock only the totals",

    "aside.facts": "This election",
    "facts.authorities": "{q} of {n} independent authorities must sign every block",
    "facts.trustees": "{k} of {n} trustees are needed to unlock the result",
    "facts.roll": "Electoral roll fingerprint",

    "foot.how": "How verification works",
    "err.load": "Could not load the election: {reason}",
    "phase.setup": "This election has not opened yet. Come back when the commission opens the poll.",
    "phase.scheduled": "Voting opens at {when}.",
    "phase.closed": "Voting has closed. You can still verify a ballot you cast.",

    "qr.title": "Check this ballot on your phone (recommended)",
    "qr.body": "Scan this with your phone camera before you cast or test. Your phone then checks the public record by itself, so it does not have to trust this device.",
    "qr.after": "Keep the phone page open. It confirms your ballot within a minute of casting.",
    "qr.link": "Cannot scan? Open this link on another device:",
    "qr.receiptTitle": "Confirm on your phone",
    "qr.receiptBody": "Scan to confirm, on a device you trust, that this exact ballot is in the public record.",

    "ck.title": "Checking a ballot",
    "ck.lede": "This phone reads the public record directly. It does not trust the device you are voting on.",
    "ck.compare": "Your voting screen must show this same code:",
    "ck.badLink": "This link is incomplete. Scan the QR code on your voting screen again.",
    "ck.waiting": "Waiting for your decision",
    "ck.waitingBody": "On your voting device, choose “Cast my vote” or “Test this ballot instead”. This page updates by itself.",
    "ck.waitingLong": "If you cast or tested more than a minute ago and this has not changed, your ballot was not recorded as shown. Do not trust that device; ask an election official.",
    "ck.tested": "This tested ballot contained:",
    "ck.testedAsk": "Is this exactly what you selected?",
    "ck.testedYes": "Yes: the device locked your choice honestly. Go back, choose again, and scan the new code before you cast.",
    "ck.testedNo": "No: your voting device changed your vote. Do not vote on it. Report it to the election officials.",
    "ck.testedNothing": "No option",
    "ck.testFail": "This ballot failed the test",
    "ck.testFailBody": "What the device revealed does not match the ballot it showed you. Do not vote on that device. Report it to the election officials.",
    "ck.cast": "Recorded exactly as shown",
    "ck.castBody": "Your ballot is sealed in block {block}, signed by {sigs} of {total} independent authorities, and it is exactly the ballot this code refers to. Your choice stays secret: this check cannot show it, and neither can anyone else.",
    "ck.castFail": "This is not the ballot you were shown",
    "ck.castFailBody": "The ballot in the public record does not match the code on your voting screen. Your vote may have been changed. Report it to the election officials.",
    "ck.details": "Technical details",
    "ck.loadErr": "Could not reach the public record: {reason}",
    "ck.wrongElection": "This code is for a different election than this site is running.",
    "ck.insecure": "This page must be opened over a secure (https) address to check a ballot. Ask the election officials for the correct link.",
    "wt.confirmed": "Confirmed by {k} of {n} independent observers ({names}). Each checked its own copy of the record; this phone asked them directly.",
    "wt.pending": "Waiting for the independent observers to confirm this block. This page checks again by itself.",
    "wt.failed": "The independent observers did not see this record",
    "wt.failedBody": "Your ballot was shown on a record that the observers never signed. Someone may be showing you a private copy. Report this to the election officials, with your tracking code.",
    "wt.none": "This election has no independent observers, so a private copy of the record shown only to you could not be detected.",
    "wt.alarm": "Observer {w} has raised an alarm: {alarm}",
    "wt.fingerprint": "Election fingerprint {fp}. It must match the one published by the election commission and the observers.",
  },

  hi: {
    "lang.switch": "English",
    "lang.switchLabel": "View this page in English",
    "skip": "मतदान पर जाएँ",
    "nav.vote": "मतदान", "nav.verify": "मतपत्र जाँचें", "nav.results": "परिणाम", "nav.record": "सार्वजनिक रिकॉर्ड",
    "bar.loading": "चुनाव लोड हो रहा है…",
    "status.setup": "अभी शुरू नहीं हुआ", "status.scheduled": "जल्द शुरू होगा", "status.voting": "मतदान जारी है",
    "status.closed": "मतदान समाप्त", "status.published": "परिणाम प्रकाशित",
    "rule.exactly": "ठीक {n} चुनें", "rule.range": "{min} से {max} चुनें", "rule.upTo": "अधिकतम {n} चुनें",
    "closes": "{when} को बंद होगा",
    "rail.identify": "पहचान", "rail.choose": "चुनाव", "rail.confirm": "जाँच", "rail.done": "रसीद",

    "id.title": "पुष्टि करें कि आप मतदान कर सकते हैं",
    "id.lede": "अपनी मतदाता पर्ची पर छपी जानकारी भरें।",
    "id.roll": "क्रमांक (रोल नंबर)", "id.rollHelp": "आपकी मतदाता पर्ची पर, जैसे R-100001",
    "id.code": "नामांकन कोड", "id.codeHelp": "डैश, स्पेस और बड़े-छोटे अक्षरों से फ़र्क नहीं पड़ता",
    "id.codePh": "अपना कोड दर्ज करें",
    "id.go": "मतपत्र पर जाएँ", "id.busy": "आपका गुमनाम मतदान पास बन रहा है…",
    "id.missing": "रोल नंबर और नामांकन कोड, दोनों भरें।",
    "id.keep": "मत डालने तक यह टैब खुला रखें। आपका मतदान पास केवल इसी टैब में है; पेज दोबारा लोड करने पर यह खो जाएगा, और आपकी पर्ची दोबारा काम नहीं करेगी।",

    "ch.title": "आपका मतपत्र",
    "ch.lede": "अपना विकल्प चुनें। कुछ भी भेजे जाने से पहले यह इसी डिवाइस पर लॉक (एन्क्रिप्ट) हो जाता है।",
    "ch.sheet": "मतपत्र",
    "ch.select": "चुनें", "ch.selected": "चुना गया",
    "ch.nota": "इनमें से कोई नहीं (नोटा)",
    "ch.go": "अपना चुनाव जाँचें", "ch.busy": "आपका चुनाव इस डिवाइस पर लॉक हो रहा है…",
    "ch.ruleOne": "ठीक एक विकल्प चुनें।",
    "ch.ruleExact": "ठीक {n} विकल्प चुनें।",
    "ch.ruleRange": "{min} से {max} विकल्प चुनें।",
    "ch.nothingSent": "अभी तक कुछ भी नहीं भेजा गया है।",

    "rv.title": "जाँचें, फिर मत डालें",
    "rv.lede": "आपके डिवाइस ने यही चुनाव लॉक किया है। सुनिश्चित करें कि यह सही है।",
    "rv.yourChoice": "आपका चुनाव", "rv.noChoice": "कोई विकल्प नहीं चुना",
    "rv.check": "मतपत्र जाँच कोड", "rv.checkHelp": "इस लॉक किए गए मतपत्र का छोटा कोड। आप इसे दूसरे डिवाइस पर मिला सकते हैं।",
    "rv.fullCode": "पूरा फ़िंगरप्रिंट दिखाएँ",
    "rv.cast": "मेरा मत डालें", "rv.casting": "मत डाला जा रहा है…",
    "rv.change": "चुनाव बदलें",
    "rv.auditTitle": "संदेह है कि ऐप ने आपका चुनाव ही लॉक किया?",
    "rv.auditBody": "मत डालने के बजाय आप इस मतपत्र की जाँच कर सकते हैं। तब ऐप को बताना होगा कि उसने आपका चुनाव कैसे लॉक किया, ताकि उसे परखा जा सके। जाँचा गया मतपत्र गिना नहीं जाता, इसलिए बाद में आप दोबारा मत डालेंगे।",
    "rv.audit": "मत डालने के बजाय जाँचें", "rv.auditing": "जाँच हो रही है…",
    "rv.auditOk": "जाँच सफल: इस मतपत्र में सचमुच आपका ही चुनाव था। जाँच में इसका उपयोग हो चुका है। नया मतपत्र डालने के लिए दोबारा चुनें।",
    "rv.auditBad": "चेतावनी: इस डिवाइस का उपयोग न करें। जाँच विफल रही: {reason}",

    "dn.kicker": "मत डाला गया",
    "dn.title": "आपका मत डाल दिया गया है",
    "dn.lede": "अपना ट्रैकिंग कोड संभालकर रखें। यह साबित करता है कि आपका मतपत्र सार्वजनिक रिकॉर्ड में है, बिना यह बताए कि आपने किसे मत दिया।",
    "dn.code": "ट्रैकिंग कोड",
    "dn.copy": "कॉपी करें", "dn.copied": "कॉपी हो गया।", "dn.copyFail": "कॉपी नहीं हुआ। कोड को चुनकर स्वयं कॉपी करें।",
    "dn.print": "रसीद प्रिंट या सेव करें", "dn.verify": "मेरा मतपत्र जाँचें",
    "dn.t.received": "मतपेटी को प्राप्त हुआ",
    "dn.t.receivedDetail": "आपका लॉक किया गया मतपत्र और उसके प्रमाण स्वीकार किए गए।",
    "dn.t.sealed": "सार्वजनिक रिकॉर्ड में सील किया गया",
    "dn.t.sealedWait": "स्वतंत्र प्राधिकरणों द्वारा अगले ब्लॉक पर हस्ताक्षर की प्रतीक्षा…",
    "dn.t.sealedDetail": "ब्लॉक {block}, {total} में से {sigs} स्वतंत्र प्राधिकरणों के हस्ताक्षर सहित।",
    "dn.t.counted": "प्रकाशित परिणाम में गिना गया",
    "dn.t.countedWait": "मतदान बंद होने के बाद ट्रस्टी केवल कुल योग खोलते हैं। कोई भी मतपत्र अलग से नहीं खोला जाता।",
    "dn.t.countedDetail": "परिणाम ऐसे प्रमाणों के साथ प्रकाशित है जिन्हें कोई भी दोबारा जाँच सकता है।",
    "dn.revoteSummary": "यह मत बदलना है?",
    "dn.revoteBody": "अगर किसी ने आप पर दबाव डाला, तो जब तक यह टैब खुला है आप दोबारा मत डाल सकते हैं। केवल आपका अंतिम मत गिना जाता है।",
    "dn.revote": "दोबारा मत डालें",
    "dn.receiptTitle": "डी-वोटिंग रसीद",
    "dn.receiptNote": "यह रसीद नहीं बताती कि आपने किसे मत दिया। इसे {url} पर जाँचें",

    "kn.title": "अभी कौन क्या जानता है",
    "kn.lede": "हर पक्ष केवल उतना जानता है जितना ज़रूरी है। कोई भी अकेला आपको आपके मत से नहीं जोड़ सकता।",
    "kn.device": "यह डिवाइस", "kn.ra": "पंजीकरण सेवा", "kn.box": "मतपेटी",
    "kn.validators": "स्वतंत्र प्राधिकरण", "kn.trustees": "ट्रस्टी",
    "kn.nothing": "अभी आपके बारे में कुछ नहीं",
    "kn.device.choose": "आपका गुमनाम मतदान पास, केवल मेमोरी में",
    "kn.device.confirm": "आपका चुनाव, और उसे लॉक करने वाला गुप्त मान",
    "kn.device.done": "आपका ट्रैकिंग कोड। लॉक का गुप्त मान मिटा दिया गया है",
    "kn.ra.after": "आपका रोल नंबर, और यह कि आपको पास मिला। उसने पास को बिना देखे हस्ताक्षरित किया, इसलिए वह आपका मतपत्र नहीं पहचान सकती",
    "kn.ra.before": "केवल आपका रोल नंबर देखेगी",
    "kn.box.done": "एक गुमनाम पास से आया लॉक मतपत्र। न आप कौन हैं, न आपका चुनाव",
    "kn.box.before": "अभी कुछ नहीं",
    "kn.val.done": "लॉक मतपत्र, जिसे वे जाँचकर सील करते हैं। आपका चुनाव कभी नहीं",
    "kn.val.before": "अभी कुछ नहीं",
    "kn.tr": "मतदान बंद होने तक कुछ नहीं। फिर {n} में से {k} मिलकर केवल कुल योग खोलते हैं",

    "aside.facts": "यह चुनाव",
    "facts.authorities": "हर ब्लॉक पर {n} में से {q} स्वतंत्र प्राधिकरणों के हस्ताक्षर ज़रूरी",
    "facts.trustees": "परिणाम खोलने के लिए {n} में से {k} ट्रस्टी ज़रूरी",
    "facts.roll": "मतदाता सूची की फ़िंगरप्रिंट",

    "foot.how": "जाँच कैसे काम करती है",
    "err.load": "चुनाव लोड नहीं हो सका: {reason}",
    "phase.setup": "यह चुनाव अभी शुरू नहीं हुआ है। आयोग द्वारा मतदान खोलने पर वापस आएँ।",
    "phase.scheduled": "मतदान {when} को शुरू होगा।",
    "phase.closed": "मतदान समाप्त हो चुका है। आप अपना डाला गया मतपत्र अब भी जाँच सकते हैं।",

    "qr.title": "इस मतपत्र को अपने फ़ोन पर जाँचें (सुझाया गया)",
    "qr.body": "मत डालने या जाँचने से पहले इसे अपने फ़ोन के कैमरे से स्कैन करें। फिर आपका फ़ोन स्वयं सार्वजनिक रिकॉर्ड जाँचता है, उसे इस डिवाइस पर भरोसा नहीं करना पड़ता।",
    "qr.after": "फ़ोन वाला पेज खुला रखें। मत डालने के एक मिनट के भीतर यह आपके मतपत्र की पुष्टि करता है।",
    "qr.link": "स्कैन नहीं कर पा रहे? यह लिंक किसी दूसरे डिवाइस पर खोलें:",
    "qr.receiptTitle": "अपने फ़ोन पर पुष्टि करें",
    "qr.receiptBody": "स्कैन करके किसी भरोसेमंद डिवाइस पर पुष्टि करें कि यही मतपत्र सार्वजनिक रिकॉर्ड में है।",

    "ck.title": "मतपत्र की जाँच",
    "ck.lede": "यह फ़ोन सीधे सार्वजनिक रिकॉर्ड पढ़ता है। यह उस डिवाइस पर भरोसा नहीं करता जिस पर आप मतदान कर रहे हैं।",
    "ck.compare": "आपकी मतदान स्क्रीन पर यही कोड दिखना चाहिए:",
    "ck.badLink": "यह लिंक अधूरा है। अपनी मतदान स्क्रीन का QR कोड दोबारा स्कैन करें।",
    "ck.waiting": "आपके निर्णय की प्रतीक्षा",
    "ck.waitingBody": "अपने मतदान डिवाइस पर “मेरा मत डालें” या “मत डालने के बजाय जाँचें” चुनें। यह पेज अपने आप अपडेट होगा।",
    "ck.waitingLong": "अगर आपने एक मिनट से अधिक पहले मत डाला या जाँचा और यह नहीं बदला, तो आपका मतपत्र दिखाए अनुसार दर्ज नहीं हुआ। उस डिवाइस पर भरोसा न करें; चुनाव अधिकारी से संपर्क करें।",
    "ck.tested": "इस जाँचे गए मतपत्र में यह था:",
    "ck.testedAsk": "क्या यह ठीक वही है जो आपने चुना था?",
    "ck.testedYes": "हाँ: डिवाइस ने आपका चुनाव ईमानदारी से लॉक किया। वापस जाएँ, दोबारा चुनें, और मत डालने से पहले नया कोड स्कैन करें।",
    "ck.testedNo": "नहीं: आपके मतदान डिवाइस ने आपका मत बदल दिया। उस पर मतदान न करें। चुनाव अधिकारियों को सूचित करें।",
    "ck.testedNothing": "कोई विकल्प नहीं",
    "ck.testFail": "यह मतपत्र जाँच में विफल रहा",
    "ck.testFailBody": "डिवाइस ने जो बताया वह उसके दिखाए मतपत्र से मेल नहीं खाता। उस डिवाइस पर मतदान न करें। चुनाव अधिकारियों को सूचित करें।",
    "ck.cast": "ठीक वैसा ही दर्ज हुआ जैसा दिखाया गया",
    "ck.castBody": "आपका मतपत्र ब्लॉक {block} में सील है, {total} में से {sigs} स्वतंत्र प्राधिकरणों द्वारा हस्ताक्षरित, और यह ठीक वही मतपत्र है जिसका यह कोड है। आपका चुनाव गुप्त रहता है: यह जाँच उसे नहीं दिखा सकती, और न ही कोई और।",
    "ck.castFail": "यह वह मतपत्र नहीं है जो आपको दिखाया गया था",
    "ck.castFailBody": "सार्वजनिक रिकॉर्ड का मतपत्र आपकी मतदान स्क्रीन के कोड से मेल नहीं खाता। आपका मत बदला गया हो सकता है। चुनाव अधिकारियों को सूचित करें।",
    "ck.details": "तकनीकी विवरण",
    "ck.loadErr": "सार्वजनिक रिकॉर्ड तक नहीं पहुँच सके: {reason}",
    "ck.wrongElection": "यह कोड किसी दूसरे चुनाव का है, इस साइट पर चल रहे चुनाव का नहीं।",
    "ck.insecure": "मतपत्र जाँचने के लिए यह पेज सुरक्षित (https) पते पर खोला जाना चाहिए। सही लिंक के लिए चुनाव अधिकारियों से पूछें।",
    "wt.confirmed": "{n} में से {k} स्वतंत्र पर्यवेक्षकों ({names}) द्वारा पुष्टि। हर एक ने रिकॉर्ड की अपनी प्रति जाँची; इस फ़ोन ने उनसे सीधे पूछा।",
    "wt.pending": "स्वतंत्र पर्यवेक्षकों द्वारा इस ब्लॉक की पुष्टि की प्रतीक्षा। यह पेज अपने आप दोबारा जाँचेगा।",
    "wt.failed": "स्वतंत्र पर्यवेक्षकों ने यह रिकॉर्ड नहीं देखा",
    "wt.failedBody": "आपका मतपत्र ऐसे रिकॉर्ड पर दिखाया गया जिस पर पर्यवेक्षकों ने कभी हस्ताक्षर नहीं किए। हो सकता है कोई आपको निजी प्रति दिखा रहा हो। अपने ट्रैकिंग कोड के साथ चुनाव अधिकारियों को सूचित करें।",
    "wt.none": "इस चुनाव में कोई स्वतंत्र पर्यवेक्षक नहीं हैं, इसलिए केवल आपको दिखाई गई निजी प्रति पकड़ी नहीं जा सकती।",
    "wt.alarm": "पर्यवेक्षक {w} ने चेतावनी दी है: {alarm}",
    "wt.fingerprint": "चुनाव फ़िंगरप्रिंट {fp}। यह चुनाव आयोग और पर्यवेक्षकों द्वारा प्रकाशित फ़िंगरप्रिंट से मेल खाना चाहिए।",
  },
};

let current = (navigator.language || "en").toLowerCase().startsWith("hi") ? "hi" : "en";
const listeners = new Set();

export function lang() {
  return current;
}

/** Translate a key, filling {placeholders} from `vars`. Falls back to English. */
export function t(key, vars = {}) {
  const text = STRINGS[current][key] ?? STRINGS.en[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, name) => (name in vars ? String(vars[name]) : `{${name}}`));
}

/** Apply translations to every opted-in element under `root`. */
export function apply(root = document) {
  document.documentElement.lang = current;
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  for (const el of root.querySelectorAll("[data-i18n-label]")) {
    el.setAttribute("aria-label", t(el.dataset.i18nLabel));
  }
}

export function setLang(next) {
  current = next === "hi" ? "hi" : "en";
  apply();
  for (const listener of listeners) listener(current);
}

/** Re-render dynamic text whenever the language changes. */
export function onLangChange(listener) {
  listeners.add(listener);
}
