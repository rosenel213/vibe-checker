// Vibe Check: Test files
// The same practice files you graded by hand, stored here so the tests can run them automatically.
//
// Why is the text chopped into tiny pieces? The practice files contain FAKE secrets. Stored whole,
// GitHub (and other scanners) might mistake them for real leaks and block the upload. Chopped up,
// no piece looks like a secret, and they are joined back together only when the tests run.

(function (VC) {
  "use strict";
  VC.fixtures = {
    piece1: [
      { path: "practice-file.js", size: 0, text:
      "// PRA" +
      "CTICE " +
      "FILE f" +
      "or the" +
      " Vibe " +
      "Check " +
      "scanne" +
      "r.\n// " +
      "Every " +
      "secret" +
      " in th" +
      "is fil" +
      "e is F" +
      "AKE. N" +
      "one of" +
      " them " +
      "work. " +
      "Do not" +
      " repla" +
      "ce the" +
      "m with" +
      " real " +
      "ones.\n" +
      "\nimpor" +
      "t { cr" +
      "eateCl" +
      "ient }" +
      " from " +
      "\"@supa" +
      "base/s" +
      "upabas" +
      "e-js\";" +
      "\n\n// -" +
      "--- Sa" +
      "fe cod" +
      "e: the" +
      " scann" +
      "er sho" +
      "uld st" +
      "ay QUI" +
      "ET on " +
      "these " +
      "lines " +
      "----\nc" +
      "onst o" +
      "penaiK" +
      "ey = p" +
      "rocess" +
      ".env.O" +
      "PENAI_" +
      "API_KE" +
      "Y;\ncon" +
      "st str" +
      "ipeKey" +
      " = pro" +
      "cess.e" +
      "nv.STR" +
      "IPE_SE" +
      "CRET_K" +
      "EY;\nco" +
      "nst pl" +
      "acehol" +
      "der = " +
      "\"your-" +
      "api-ke" +
      "y-here" +
      "\";\ncon" +
      "st use" +
      "rId = " +
      "\"550e8" +
      "400-e2" +
      "9b-41d" +
      "4-a716" +
      "-44665" +
      "544000" +
      "0\";\nco" +
      "nst bu" +
      "ttonLa" +
      "bel = " +
      "\"Enter" +
      " your " +
      "Stripe" +
      " secre" +
      "t key\"" +
      ";\ncons" +
      "t comm" +
      "itHash" +
      " = \"9f" +
      "ceb02d" +
      "0ae598" +
      "e95dc9" +
      "70b747" +
      "67f193" +
      "72d61a" +
      "f8\";\n\n" +
      "// ---" +
      "- Dang" +
      "erous " +
      "code: " +
      "the sc" +
      "anner " +
      "should" +
      " BEEP " +
      "on the" +
      "se lin" +
      "es ---" +
      "-\ncons" +
      "t open" +
      "ai = \"" +
      "sk-pro" +
      "j-FAKE" +
      "fakeFA" +
      "KEfake" +
      "FAKEfa" +
      "keFAKE" +
      "fakeFA" +
      "KEfake" +
      "1234\";" +
      "\nconst" +
      " awsAc" +
      "cessKe" +
      "y = \"A" +
      "KIAIOS" +
      "FODNN7" +
      "EXAMPL" +
      "E\";\nco" +
      "nst aw" +
      "sSecre" +
      "tKey =" +
      " \"wJal" +
      "rXUtnF" +
      "EMI/K7" +
      "MDENG/" +
      "bPxRfi" +
      "CYEXAM" +
      "PLEKEY" +
      "\";\ncon" +
      "st str" +
      "ipe = " +
      "\"sk_li" +
      "ve_FAK" +
      "E00000" +
      "000000" +
      "000000" +
      "000000" +
      "000\";\n" +
      "const " +
      "supaba" +
      "se = c" +
      "reateC" +
      "lient(" +
      "\"https" +
      "://fak" +
      "eproje" +
      "ct.sup" +
      "abase." +
      "co\", \"" +
      "eyJhbG" +
      "ciOiJI" +
      "UzI1Ni" +
      "IsInR5" +
      "cCI6Ik" +
      "pXVCJ9" +
      ".eyJpc" +
      "3MiOiJ" +
      "zdXBhY" +
      "mFzZSI" +
      "sInJlZ" +
      "iI6ImZ" +
      "ha2Vwc" +
      "m9qZWN" +
      "0Iiwic" +
      "m9sZSI" +
      "6InNlc" +
      "nZpY2V" +
      "fcm9sZ" +
      "SIsIml" +
      "hdCI6M" +
      "TcwMDA" +
      "wMDAwM" +
      "CwiZXh" +
      "wIjoyM" +
      "DAwMDA" +
      "wMDAwf" +
      "Q.FAKE" +
      "signat" +
      "ureFAK" +
      "Esigna" +
      "tureFA" +
      "KEsign" +
      "ature0" +
      "00\");\n" +
      "const " +
      "github" +
      "Token " +
      "= \"ghp" +
      "_FAKE0" +
      "000000" +
      "000000" +
      "000000" +
      "000000" +
      "000FAK" +
      "E\";\nco" +
      "nst db" +
      "Url = " +
      "\"postg" +
      "resql:" +
      "//post" +
      "gres:F" +
      "akePas" +
      "sword1" +
      "23@db." +
      "fakepr" +
      "oject." +
      "supaba" +
      "se.co:" +
      "5432/p" +
      "ostgre" +
      "s\";\nco" +
      "nst pr" +
      "ivateK" +
      "ey = `" +
      "-----B" +
      "EGIN R" +
      "SA PRI" +
      "VATE K" +
      "EY----" +
      "-\nFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "\n-----" +
      "END RS" +
      "A PRIV" +
      "ATE KE" +
      "Y-----" +
      "`;\n" },
    ],
    piece2: [
      { path: ".env", size: 254, text:
      "# PRAC" +
      "TICE F" +
      "ILE. E" +
      "very s" +
      "ecret " +
      "here i" +
      "s FAKE" +
      ".\nNEXT" +
      "_PUBLI" +
      "C_SUPA" +
      "BASE_U" +
      "RL=htt" +
      "ps://f" +
      "akepro" +
      "ject.s" +
      "upabas" +
      "e.co\nS" +
      "TRIPE_" +
      "SECRET" +
      "_KEY=s" +
      "k_live" +
      "_FAKE1" +
      "111111" +
      "111111" +
      "111111" +
      "111111" +
      "1\nDATA" +
      "BASE_U" +
      "RL=pos" +
      "tgresq" +
      "l://po" +
      "stgres" +
      ":FakeR" +
      "ealPas" +
      "sword9" +
      "87@db." +
      "fakepr" +
      "oject." +
      "supaba" +
      "se.co:" +
      "5432/p" +
      "ostgre" +
      "s\n" },
      { path: ".env.example", size: 237, text:
      "# Temp" +
      "late f" +
      "or oth" +
      "er dev" +
      "eloper" +
      "s. The" +
      "se are" +
      " place" +
      "holder" +
      "s, not" +
      " secre" +
      "ts.\nOP" +
      "ENAI_A" +
      "PI_KEY" +
      "=your-" +
      "openai" +
      "-key-h" +
      "ere\nST" +
      "RIPE_S" +
      "ECRET_" +
      "KEY=yo" +
      "ur-str" +
      "ipe-ke" +
      "y-here" +
      "\nDATAB" +
      "ASE_UR" +
      "L=post" +
      "gresql" +
      "://pos" +
      "tgres:" +
      "[YOUR-" +
      "PASSWO" +
      "RD]@db" +
      ".yourp" +
      "roject" +
      ".supab" +
      "ase.co" +
      ":5432/" +
      "postgr" +
      "es\n" },
      { path: "README.md", size: 101, text:
      "# My V" +
      "ibe Ap" +
      "p\n\nSet" +
      " your " +
      "OpenAI" +
      " key i" +
      "n `.en" +
      "v` (it" +
      " start" +
      "s with" +
      " `sk-." +
      "..`).\n" +
      "Never " +
      "commit" +
      " your " +
      "real k" +
      "eys.\n" },
      { path: "keys/server.pem", size: 119, text:
      "-----B" +
      "EGIN P" +
      "RIVATE" +
      " KEY--" +
      "---\nFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KEFAKE" +
      "FAKEFA" +
      "KE\n---" +
      "--END " +
      "PRIVAT" +
      "E KEY-" +
      "----\n" },
      { path: "node_modules/fake-lib/index.js", size: 102, text:
      "// Thi" +
      "s fold" +
      "er sho" +
      "uld be" +
      " SKIPP" +
      "ED by " +
      "the sc" +
      "anner," +
      " not r" +
      "eporte" +
      "d.\ncon" +
      "st aws" +
      "Key = " +
      "\"AKIAF" +
      "AKEFAK" +
      "EFAKEF" +
      "AKE\";\n" },
      { path: "package.json", size: 46, text:
      "{ \"nam" +
      "e\": \"m" +
      "y-vibe" +
      "-app\"," +
      " \"vers" +
      "ion\": " +
      "\"1.0.0" +
      "\" }\n" },
      { path: "public/logo.png", size: 8, text:
      "" },
      { path: "src/api/chat.js", size: 340, text:
      "// PRA" +
      "CTICE " +
      "FILE. " +
      "Every " +
      "secret" +
      " here " +
      "is FAK" +
      "E.\nimp" +
      "ort Op" +
      "enAI f" +
      "rom \"o" +
      "penai\"" +
      ";\n\n// " +
      "The co" +
      "rrect " +
      "way: k" +
      "ey com" +
      "es fro" +
      "m the " +
      "enviro" +
      "nment\n" +
      "const " +
      "safeCl" +
      "ient =" +
      " new O" +
      "penAI(" +
      "{ apiK" +
      "ey: pr" +
      "ocess." +
      "env.OP" +
      "ENAI_A" +
      "PI_KEY" +
      " });\n\n" +
      "// The" +
      " vibe-" +
      "coded " +
      "way: k" +
      "ey pas" +
      "ted st" +
      "raight" +
      " in\nco" +
      "nst le" +
      "akyCli" +
      "ent = " +
      "new Op" +
      "enAI({" +
      " apiKe" +
      "y: \"sk" +
      "-proj-" +
      "FAKEch" +
      "atFAKE" +
      "chatFA" +
      "KEchat" +
      "FAKEch" +
      "atFAKE" +
      "5678\" " +
      "});\n" },
      { path: "src/config.js", size: 209, text:
      "// PRA" +
      "CTICE " +
      "FILE. " +
      "Every " +
      "secret" +
      " here " +
      "is FAK" +
      "E.\nexp" +
      "ort co" +
      "nst co" +
      "nfig =" +
      " {\n  a" +
      "ppName" +
      ": \"My " +
      "Vibe A" +
      "pp\",\n " +
      " \"task" +
      "-list-" +
      "contai" +
      "ner-cl" +
      "ass-na" +
      "me-ver" +
      "y-long" +
      "\": tru" +
      "e,\n  g" +
      "ithubT" +
      "oken: " +
      "\"ghp_F" +
      "AKE111" +
      "111111" +
      "111111" +
      "111111" +
      "111111" +
      "1FAKE\"" +
      ",\n};\n" },
      { path: "src/lib/supabase.js", size: 774, text:
      "// PRA" +
      "CTICE " +
      "FILE. " +
      "Every " +
      "secret" +
      " here " +
      "is FAK" +
      "E.\nimp" +
      "ort { " +
      "create" +
      "Client" +
      " } fro" +
      "m \"@su" +
      "pabase" +
      "/supab" +
      "ase-js" +
      "\";\n\n//" +
      " Publi" +
      "c \"ano" +
      "n\" key" +
      ": mean" +
      "t to b" +
      "e publ" +
      "ic, sh" +
      "ould N" +
      "OT be " +
      "flagge" +
      "d\nexpo" +
      "rt con" +
      "st pub" +
      "licCli" +
      "ent = " +
      "create" +
      "Client" +
      "(\"http" +
      "s://fa" +
      "keproj" +
      "ect.su" +
      "pabase" +
      ".co\", " +
      "\"eyJhb" +
      "GciOiJ" +
      "IUzI1N" +
      "iIsInR" +
      "5cCI6I" +
      "kpXVCJ" +
      "9.eyJp" +
      "c3MiOi" +
      "JzdXBh" +
      "YmFzZS" +
      "IsInJl" +
      "ZiI6Im" +
      "Zha2Vw" +
      "cm9qZW" +
      "N0Iiwi" +
      "cm9sZS" +
      "I6ImFu" +
      "b24iLC" +
      "JpYXQi" +
      "OjE3MD" +
      "AwMDAw" +
      "MDAsIm" +
      "V4cCI6" +
      "MjAwMD" +
      "AwMDAw" +
      "MH0.FA" +
      "KEsign" +
      "atureF" +
      "AKEsig" +
      "nature" +
      "FAKEsi" +
      "gnatur" +
      "e111\")" +
      ";\n\n// " +
      "Servic" +
      "e-role" +
      " key i" +
      "n brow" +
      "ser co" +
      "de: DA" +
      "NGEROU" +
      "S\nexpo" +
      "rt con" +
      "st adm" +
      "inClie" +
      "nt = c" +
      "reateC" +
      "lient(" +
      "\"https" +
      "://fak" +
      "eproje" +
      "ct.sup" +
      "abase." +
      "co\", \"" +
      "eyJhbG" +
      "ciOiJI" +
      "UzI1Ni" +
      "IsInR5" +
      "cCI6Ik" +
      "pXVCJ9" +
      ".eyJpc" +
      "3MiOiJ" +
      "zdXBhY" +
      "mFzZSI" +
      "sInJlZ" +
      "iI6ImZ" +
      "ha2Vwc" +
      "m9qZWN" +
      "0Iiwic" +
      "m9sZSI" +
      "6InNlc" +
      "nZpY2V" +
      "fcm9sZ" +
      "SIsIml" +
      "hdCI6M" +
      "TcwMDA" +
      "wMDAwM" +
      "CwiZXh" +
      "wIjoyM" +
      "DAwMDA" +
      "wMDAwf" +
      "Q.FAKE" +
      "signat" +
      "ureFAK" +
      "Esigna" +
      "tureFA" +
      "KEsign" +
      "ature0" +
      "00\");\n" },
    ],
    gitignore: [
      { path: "a-no-gitignore/.env", size: 20, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "a\n" },
      { path: "b-old-nextjs/.env", size: 20, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "b\n" },
      { path: "b-old-nextjs/.env.local", size: 26, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "b-loca" +
      "l\n" },
      { path: "b-old-nextjs/.gitignore", size: 47, text:
      "# old " +
      "Next.j" +
      "s defa" +
      "ult\n.e" +
      "nv*.lo" +
      "cal\nno" +
      "de_mod" +
      "ules\n" },
      { path: "c-protected/.env", size: 20, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "c\n" },
      { path: "c-protected/.env.example", size: 23, text:
      "APP_NA" +
      "ME=you" +
      "r-app-" +
      "name\n" },
      { path: "c-protected/.gitignore", size: 20, text:
      ".env*\n" +
      "!.env." +
      "exampl" +
      "e\n" },
      { path: "d-nested/.env", size: 20, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "d\n" },
      { path: "d-nested/.gitignore", size: 61, text:
      "/.env\n" +
      "# .env" +
      " files" +
      " in ap" +
      "p/ are" +
      " not c" +
      "overed" +
      " by th" +
      "e rule" +
      " above" +
      "\n" },
      { path: "d-nested/app/.env", size: 24, text:
      "APP_NA" +
      "ME=pra" +
      "ctice-" +
      "d-app\n" },
    ],
    public: [
      { path: ".env", size: 487, text:
      "# PRAC" +
      "TICE F" +
      "ILE. V" +
      "alues " +
      "are pl" +
      "acehol" +
      "ders, " +
      "not re" +
      "al key" +
      "s.\nNEX" +
      "T_PUBL" +
      "IC_SUP" +
      "ABASE_" +
      "URL=ht" +
      "tps://" +
      "fakepr" +
      "oject." +
      "supaba" +
      "se.co\n" +
      "NEXT_P" +
      "UBLIC_" +
      "SUPABA" +
      "SE_ANO" +
      "N_KEY=" +
      "placeh" +
      "older-" +
      "anon-k" +
      "ey\nNEX" +
      "T_PUBL" +
      "IC_STR" +
      "IPE_PU" +
      "BLISHA" +
      "BLE_KE" +
      "Y=plac" +
      "eholde" +
      "r-publ" +
      "ishabl" +
      "e-key\n" +
      "NEXT_P" +
      "UBLIC_" +
      "OPENAI" +
      "_API_K" +
      "EY=pla" +
      "cehold" +
      "er-ope" +
      "nai-ke" +
      "y\nNEXT" +
      "_PUBLI" +
      "C_SUPA" +
      "BASE_S" +
      "ERVICE" +
      "_ROLE_" +
      "KEY=pl" +
      "acehol" +
      "der-se" +
      "rvice-" +
      "role-k" +
      "ey\nNEX" +
      "T_PUBL" +
      "IC_STR" +
      "IPE_SE" +
      "CRET_K" +
      "EY=pla" +
      "cehold" +
      "er-str" +
      "ipe-se" +
      "cret\nN" +
      "EXT_PU" +
      "BLIC_S" +
      "ECRETA" +
      "RY_NAM" +
      "E=Jane" +
      "\nNEXT_" +
      "PUBLIC" +
      "_FIREB" +
      "ASE_AP" +
      "I_KEY=" +
      "placeh" +
      "older-" +
      "fireba" +
      "se-key" +
      "\n" },
      { path: ".gitignore", size: 20, text:
      ".env*\n" +
      "!.env." +
      "exampl" +
      "e\n" },
      { path: "src/chat.js", size: 210, text:
      "// PRA" +
      "CTICE " +
      "FILE.\n" +
      "// Wro" +
      "ng: th" +
      "is key" +
      " name " +
      "is pub" +
      "lic, s" +
      "o the " +
      "key en" +
      "ds up " +
      "in the" +
      " brows" +
      "er\ncon" +
      "st lea" +
      "ky = p" +
      "rocess" +
      ".env.N" +
      "EXT_PU" +
      "BLIC_O" +
      "PENAI_" +
      "API_KE" +
      "Y;\n\n//" +
      " Right" +
      ": serv" +
      "er-onl" +
      "y name" +
      "\nconst" +
      " safe " +
      "= proc" +
      "ess.en" +
      "v.OPEN" +
      "AI_API" +
      "_KEY;\n" },
      { path: "vite-app/src/ai.js", size: 181, text:
      "// PRA" +
      "CTICE " +
      "FILE. " +
      "A Vite" +
      " app (" +
      "the ki" +
      "nd Lov" +
      "able a" +
      "nd Bol" +
      "t make" +
      ").\ncon" +
      "st sup" +
      "abaseK" +
      "ey = i" +
      "mport." +
      "meta.e" +
      "nv.VIT" +
      "E_SUPA" +
      "BASE_A" +
      "NON_KE" +
      "Y;\ncon" +
      "st cla" +
      "udeKey" +
      " = imp" +
      "ort.me" +
      "ta.env" +
      ".VITE_" +
      "ANTHRO" +
      "PIC_AP" +
      "I_KEY;" +
      "\n" },
    ],
    rlsWithSql: [
      { path: ".gitignore", size: 20, text:
      ".env*\n" +
      "!.env." +
      "exampl" +
      "e\n" },
      { path: "package.json", size: 58, text:
      "{ \"dep" +
      "endenc" +
      "ies\": " +
      "{ \"@su" +
      "pabase" +
      "/supab" +
      "ase-js" +
      "\": \"^2" +
      ".0.0\" " +
      "} }\n" },
      { path: "supabase/migrations/20240101000000_init.sql", size: 576, text:
      "-- PRA" +
      "CTICE " +
      "FILE: " +
      "databa" +
      "se set" +
      "up for" +
      " a fak" +
      "e app\n" +
      "\ncreat" +
      "e tabl" +
      "e publ" +
      "ic.pro" +
      "files " +
      "(\n  id" +
      " uuid " +
      "primar" +
      "y key," +
      "\n  nam" +
      "e text" +
      "\n);\nal" +
      "ter ta" +
      "ble pu" +
      "blic.p" +
      "rofile" +
      "s enab" +
      "le row" +
      " level" +
      " secur" +
      "ity;\n\n" +
      "create" +
      " table" +
      " todos" +
      " (\n  i" +
      "d bigi" +
      "nt pri" +
      "mary k" +
      "ey,\n  " +
      "title " +
      "text\n)" +
      ";\n\ncre" +
      "ate ta" +
      "ble if" +
      " not e" +
      "xists " +
      "\"publi" +
      "c\".\"me" +
      "ssages" +
      "\" (\n  " +
      "id big" +
      "int pr" +
      "imary " +
      "key,\n " +
      " body " +
      "text\n)" +
      ";\n\ncre" +
      "ate ta" +
      "ble pr" +
      "ivate." +
      "audit_" +
      "log (\n" +
      "  id b" +
      "igint " +
      "primar" +
      "y key\n" +
      ");\n\n--" +
      " creat" +
      "e tabl" +
      "e comm" +
      "ented_" +
      "out (i" +
      "d int)" +
      ";\n\ncre" +
      "ate ta" +
      "ble or" +
      "ders (" +
      "\n  id " +
      "bigint" +
      " prima" +
      "ry key" +
      ",\n  to" +
      "tal nu" +
      "meric\n" +
      ");\nalt" +
      "er tab" +
      "le ord" +
      "ers en" +
      "able r" +
      "ow lev" +
      "el sec" +
      "urity;" +
      "\n\ncrea" +
      "te tab" +
      "le tem" +
      "p_stuf" +
      "f (id " +
      "int);\n" },
      { path: "supabase/migrations/20240201000000_more.sql", size: 176, text:
      "-- Sec" +
      "ond se" +
      "tup fi" +
      "le, ru" +
      "ns aft" +
      "er the" +
      " first" +
      " one\na" +
      "lter t" +
      "able \"" +
      "public" +
      "\".\"mes" +
      "sages\"" +
      " enabl" +
      "e row " +
      "level " +
      "securi" +
      "ty;\nal" +
      "ter ta" +
      "ble or" +
      "ders d" +
      "isable" +
      " row l" +
      "evel s" +
      "ecurit" +
      "y;\ndro" +
      "p tabl" +
      "e temp" +
      "_stuff" +
      ";\n" },
    ],
    rlsInnerFolder: [
      { path: "migrations/20240101000000_init.sql", size: 576, text:
      "-- PRA" +
      "CTICE " +
      "FILE: " +
      "databa" +
      "se set" +
      "up for" +
      " a fak" +
      "e app\n" +
      "\ncreat" +
      "e tabl" +
      "e publ" +
      "ic.pro" +
      "files " +
      "(\n  id" +
      " uuid " +
      "primar" +
      "y key," +
      "\n  nam" +
      "e text" +
      "\n);\nal" +
      "ter ta" +
      "ble pu" +
      "blic.p" +
      "rofile" +
      "s enab" +
      "le row" +
      " level" +
      " secur" +
      "ity;\n\n" +
      "create" +
      " table" +
      " todos" +
      " (\n  i" +
      "d bigi" +
      "nt pri" +
      "mary k" +
      "ey,\n  " +
      "title " +
      "text\n)" +
      ";\n\ncre" +
      "ate ta" +
      "ble if" +
      " not e" +
      "xists " +
      "\"publi" +
      "c\".\"me" +
      "ssages" +
      "\" (\n  " +
      "id big" +
      "int pr" +
      "imary " +
      "key,\n " +
      " body " +
      "text\n)" +
      ";\n\ncre" +
      "ate ta" +
      "ble pr" +
      "ivate." +
      "audit_" +
      "log (\n" +
      "  id b" +
      "igint " +
      "primar" +
      "y key\n" +
      ");\n\n--" +
      " creat" +
      "e tabl" +
      "e comm" +
      "ented_" +
      "out (i" +
      "d int)" +
      ";\n\ncre" +
      "ate ta" +
      "ble or" +
      "ders (" +
      "\n  id " +
      "bigint" +
      " prima" +
      "ry key" +
      ",\n  to" +
      "tal nu" +
      "meric\n" +
      ");\nalt" +
      "er tab" +
      "le ord" +
      "ers en" +
      "able r" +
      "ow lev" +
      "el sec" +
      "urity;" +
      "\n\ncrea" +
      "te tab" +
      "le tem" +
      "p_stuf" +
      "f (id " +
      "int);\n" },
      { path: "migrations/20240201000000_more.sql", size: 176, text:
      "-- Sec" +
      "ond se" +
      "tup fi" +
      "le, ru" +
      "ns aft" +
      "er the" +
      " first" +
      " one\na" +
      "lter t" +
      "able \"" +
      "public" +
      "\".\"mes" +
      "sages\"" +
      " enabl" +
      "e row " +
      "level " +
      "securi" +
      "ty;\nal" +
      "ter ta" +
      "ble or" +
      "ders d" +
      "isable" +
      " row l" +
      "evel s" +
      "ecurit" +
      "y;\ndro" +
      "p tabl" +
      "e temp" +
      "_stuff" +
      ";\n" },
    ],
    rlsWithoutSql: [
      { path: ".gitignore", size: 6, text:
      ".env*\n" },
      { path: "package.json", size: 58, text:
      "{ \"dep" +
      "endenc" +
      "ies\": " +
      "{ \"@su" +
      "pabase" +
      "/supab" +
      "ase-js" +
      "\": \"^2" +
      ".0.0\" " +
      "} }\n" },
      { path: "src/db.js", size: 234, text:
      "// PRA" +
      "CTICE " +
      "FILE. " +
      "Tables" +
      " were " +
      "made i" +
      "n the " +
      "Supaba" +
      "se web" +
      "site, " +
      "so the" +
      "re are" +
      " no se" +
      "tup fi" +
      "les.\ni" +
      "mport " +
      "{ crea" +
      "teClie" +
      "nt } f" +
      "rom \"@" +
      "supaba" +
      "se/sup" +
      "abase-" +
      "js\";\ne" +
      "xport " +
      "const " +
      "db = c" +
      "reateC" +
      "lient(" +
      "\"https" +
      "://fak" +
      "eproje" +
      "ct.sup" +
      "abase." +
      "co\", \"" +
      "placeh" +
      "older-" +
      "anon-k" +
      "ey\");\n" },
    ],
  };
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
