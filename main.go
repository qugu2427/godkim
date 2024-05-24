package main

import "fmt"

// const testDkimHeader string = `v=1; a=rsa-sha256;
// d=example.com; s=big-email;
// h=from:to:subject;
// bh=uMixy0BsCqhbru4fqPZQdeZY5Pq865sNAnOAxNgUS0s=;
// b=LiIvJeRyqMo0gngiCygwpiKphJjYezb5kXBKCNj8DqRVcCk7obK6OUg4o+EufEbB
// tRYQfQhgIkx5m70IqA6dP+DBZUcsJyS9C+vm2xRK7qyHi2hUFpYS5pkeiNVoQk/Wk4w
// ZG4tu/g+OA49mS7VX+64FXr79MPwOMRRmJ3lNwJU=`

const rawEmail string = "Received: by mail-oo1-f42.google.com with SMTP id 006d021491bc7-598be762780so2476716eaf.0\r\n        for <admin@llillii.li>; Mon, 15 Jan 2024 15:16:09 -0800 (PST)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=colorado.edu; s=google; t=1705360569; x=1705965369; darn=llillii.li;\r\n        h=to:subject:message-id:date:from:reply-to:mime-version:from:to:cc\r\n         :subject:date:message-id:reply-to;\r\n        bh=tfDE7NK8oIhTax07knTNmwC8mQFtGDhL/Zt6ZU9sOLs=;\r\n        b=QaLQSzWKOPZaEeNwExEdDtO0y1xXTKtG4AqWa46U1UFIugXzNn7MPjv+roWW0BeJyY\r\n         fnmEuQgnc2DPko8U2E/B/epq2svunZ8DlBND1pFj6Gj2G4dsz8Otf2D7JQKF2tpv7NKD\r\n         avUb2vICifpfYJc1VpP5i0+SHdjKGj/dXy0+2r6W2jMWfx8IxQdzncu1H6zXfRklkAsK\r\n         PEiZ61bNbHn0fkd9YSxUwX1mKxDbM1qOKfw1Ncbe7KqNURenwc2EMWCWu3xCRrB0upkm\r\n         lz8C3/01BK3cuqfngz0wWOqT8HxFOCvNoVgrzwJB7heQcGGwI+NPGf8tczFrHoBPUFde\r\n         BZsw==\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20230601; t=1705360569; x=1705965369;\r\n        h=to:subject:message-id:date:from:reply-to:mime-version\r\n         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;\r\n        bh=tfDE7NK8oIhTax07knTNmwC8mQFtGDhL/Zt6ZU9sOLs=;\r\n        b=RDLPkCA2Xkl9uh2WYHxWfOBr/Vwy0vs0KaUlH/nR+K6lD6Jto0zmsYD7ir8rvCYq8Y\r\n         D5vq0p70eDA0X0Loy5Qa3YCDLw9nrpJgbZpqxr8TwcibTSbVc8qPBWG2vSEG2GTR9AXd\r\n         Yeal/BSnS3tfO2zgeldYHDbH/gZFWpShFDgEvR4Lm2j3cVbluAPuTO+OF9zJGIZF0/g6\r\n         fGdGDKZHgzcE/awK/HENHXaAM6vJevpvBFV9rD6V34y6NbdI1rvdwwTTMB2jGYu6RHM1\r\n         fId6XVpEkSZGilDd91VeXti/jYEZucH8C+Fy3BZx8Uwa7OB3oW+oRQYHSq5oohKmQghL\r\n         xARQ==\r\nX-Gm-Message-State: AOJu0YwAOVUABbLpyKhG/frRQiqH1rhXXPxKDHczeeayu+2QL52xaLyB\r\n\tVDjJ19kwn1Ee84TdxKv39HkhwHKyLacR92KUF4lzKshDz/BtbokIkE3bI38KUIFLzbv3tcVK\r\nX-Google-Smtp-Source: AGHT+IGNyVg16llQaHsVXyrNUq6HoXppTRWIWj8aYu3nl6+ZwXi0oG67X76Exjr7xowX/SbzCYu0WAohb/sdN8pTdcQ=\r\nX-Received: by 2002:a4a:a586:0:b0:599:886:fb4d with SMTP id\r\n d6-20020a4aa586000000b005990886fb4dmr1290217oom.18.1705360569083; Mon, 15 Jan\r\n 2024 15:16:09 -0800 (PST)\r\nMIME-Version: 1.0\r\nReply-To: Quinn.Guerin@colorado.edu\r\nFrom: Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nDate: Mon, 15 Jan 2024 23:15:58 +0000\r\nMessage-ID: <CAKDWnjcP=VPDcRZ_BS_J6QSg01nF-7gwUevNz7mNP6Hremb3NA@mail.gmail.com>\r\nSubject: fwe\r\nTo: admin@llillii.li\r\nContent-Type: multipart/alternative; boundary=\"000000000000ef3bd0060f0432a6\"\r\n\r\n--000000000000ef3bd0060f0432a6\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nfwefew\r\n\r\n--000000000000ef3bd0060f0432a6\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">fwefew<br></div>\r\n\r\n--000000000000ef3bd0060f0432a6--\r\n.\r\n"

// const unsignedEmail string = "MIME-Version: 1.0\r\nDate: Fri, 24 May 2024 10:19:18 -0600\r\nReply-To: Quinn.Guerin@colorado.edu\r\nMessage-ID: <CAKDWnjdpV1JGJSBDR_ye4nNzoiL509vuOK5ntZKvq7GezkiGTg@mail.gmail.com>\r\nSubject: Test Email\r\nFrom: Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nTo: qugu24727@colorado.edu\r\nContent-Type: multipart/alternative; boundary=\"00000000000095c7110619358760\"\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nthis is a test email\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">this is a test email</div>\r\n\r\n--00000000000095c7110619358760--"

//const rawEmail string = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=proton.me;\r\n\ts=protonmail; t=1705267358; x=1705526558;\r\n\tbh=KJA/mIHYk1QBPCy5bmzsGkLPBp3zKu7pEghy7IrdcPg=;\r\n\th=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:\r\n\t Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector;\r\n\tb=hNZLOc5waZV3u0oO61hH+DlZdAdMMbs1fb0i2fXrfvsGmuOnIz0j/c4+4EJjIytxo\r\n\t TlgbxP+5otg6sghIKfagYI+7NaS8EDWfT4n9oMtI28OfJZrigkvWcJZzeR2hvbMG0O\r\n\t pRV8s9/CN7hTE58+AkgEPaUjuFnscS4M6EUx1ryb0tMnqLtvaVhp8Us3UFfbK9glQY\r\n\t 3bwx0waNu4P1KDCYE9iIVQplYyuFvKudH6GkEx5QRudVX+CZPHavY+5lv1n2KTZ0ZL\r\n\t 8Qd//NbOEuq2EYSYdxGyqIVcXFmzi+6TVzTLxxRPcuImRa5aqLtN9TT8Q3QswbeJiC\r\n\t 48RZAVdrsk01Q==\r\nDate: Sun, 14 Jan 2024 21:22:24 +0000\r\nTo: \"admin@llillii.li\" <admin@llillii.li>\r\nFrom: qugu2427 <qugu2427@proton.me>\r\nSubject: dsf\r\nMessage-ID: <fMrnoH12VNhXJf9EAlVsNdTm624x0qaG50Q23h99PCxFgvk0ZersPzHdJBx_-O1fryOq33YC5X5Raz55fAqZndNLiAq2ZU7An2pM4d8g6H4=@proton.me>\r\nFeedback-ID: 85942582:user:proton\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n boundary=\"b1_1vTWc7snuz0RsdPVW4sGZoZ6yxxthnZtz778VKBjrbQ\"\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n--b1_1vTWc7snuz0RsdPVW4sGZoZ6yxxthnZtz778VKBjrbQ\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nc2Rmc2F1eWNzYQphc2Zhc2ZhZnNhc2FzZnNhCgpTZW50IHdpdGggW1Byb3RvbiBNYWlsXShodHRw\r\nczovL3Byb3Rvbi5tZS8pIHNlY3VyZSBlbWFpbC4=\r\n\r\n--b1_1vTWc7snuz0RsdPVW4sGZoZ6yxxthnZtz778VKBjrbQ\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0\r\ncHg7Ij5zZGZzYXV5Y3NhPC9kaXY+PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5z\r\nLXNlcmlmOyBmb250LXNpemU6IDE0cHg7Ij5hc2Zhc2ZhZnNhc2FzZnNhPGJyPjwvZGl2PjxkaXYg\r\nc3R5bGU9ImZvbnQtZmFtaWx5OiBBcmlhbCwgc2Fucy1zZXJpZjsgZm9udC1zaXplOiAxNHB4OyI+\r\nPGJyPjwvZGl2Pg0KPGRpdiBjbGFzcz0icHJvdG9ubWFpbF9zaWduYXR1cmVfYmxvY2siIHN0eWxl\r\nPSJmb250LWZhbWlseTogQXJpYWwsIHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTogMTRweDsiPg0KICAg\r\nIDxkaXYgY2xhc3M9InByb3Rvbm1haWxfc2lnbmF0dXJlX2Jsb2NrLXVzZXIgcHJvdG9ubWFpbF9z\r\naWduYXR1cmVfYmxvY2stZW1wdHkiPg0KICAgICAgICANCiAgICAgICAgICAgIDwvZGl2Pg0KICAg\r\nIA0KICAgICAgICAgICAgPGRpdiBjbGFzcz0icHJvdG9ubWFpbF9zaWduYXR1cmVfYmxvY2stcHJv\r\ndG9uIj4NCiAgICAgICAgU2VudCB3aXRoIDxhIHRhcmdldD0iX2JsYW5rIiBocmVmPSJodHRwczov\r\nL3Byb3Rvbi5tZS8iIHJlbD0ibm9vcGVuZXIgbm9yZWZlcnJlciI+UHJvdG9uIE1haWw8L2E+IHNl\r\nY3VyZSBlbWFpbC4NCiAgICA8L2Rpdj4NCjwvZGl2Pg0K\r\n\r\n\r\n--b1_1vTWc7snuz0RsdPVW4sGZoZ6yxxthnZtz778VKBjrbQ--\r\n\r\n.\r\n"

// const rawEmail string = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=proton.me;\r\n\ts=protonmail; t=1705632310; x=1705891510;\r\n\tbh=bgiK6lNfK6S+lYdqzqW4CXkAgkNAZMNne+zmC2MmpI8=;\r\n\th=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:\r\n\t Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector;\r\n\tb=gkQXpOyER5R8Y2XR+H5jmOeSFaP4ZqNFk5qRFFMBLc0RPr7ihdx1Q4ehTWhLITazz\r\n\t spbUkta4ejahWiWPXhNu4CssISnvhdM0V+lJE+JS9PI5l1ve9qjvCiDN4kZ6oMfJuo\r\n\t feu30Ja99JGVTwpLjZor8Ae1kLVWOhIdTWBfmbYgV4sHdUgJfrY3LVQes0SgLk/bmz\r\n\t cKlHdhEwCajqrPzBeNszZtcph60qbFWFQuW9DxqsX/k6f2GSQUKCJ1vcRbe1e8NLO4\r\n\t iizz6qzPHs8Ljnsr9WDJ4TNQsybHtQwouJts1Y8lCq1/yAHW/ELl6G4w56tZpGxJOI\r\n\t Q41z59wZI7dSA==\r\nDate: Fri, 19 Jan 2024 02:44:51 +0000\r\nTo: \"admin@llillii.li\" <admin@llillii.li>\r\nFrom: qugu2427 <qugu2427@proton.me>\r\nSubject: Test\r\nMessage-ID: <DhrC06ISvjenM5t098NtiLKIHVRz8YNp_dGeBoNV9OBNOcRl_ZbKLbNUTwm_za05eHn35kZ7K3elYDnCd_fIurFK6ryYdK3z4EzM7H2bmKI=@proton.me>\r\nFeedback-ID: 85942582:user:proton\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n boundary=\"b1_KnIaUvKotVYEBnjB5bhv9Vr3R91D02PobPELlCg1Rc\"\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n--b1_KnIaUvKotVYEBnjB5bhv9Vr3R91D02PobPELlCg1Rc\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nVGhpcyBpcyBhIHRlc3QgbWVzc2FnZS4=\r\n\r\n--b1_KnIaUvKotVYEBnjB5bhv9Vr3R91D02PobPELlCg1Rc\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0\r\ncHg7IGNvbG9yOiByZ2IoMCwgMCwgMCk7IGJhY2tncm91bmQtY29sb3I6IHJnYigyNTUsIDI1NSwg\r\nMjU1KTsiPlRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2UuPGJyPjwvZGl2Pg==\r\n\r\n\r\n--b1_KnIaUvKotVYEBnjB5bhv9Vr3R91D02PobPELlCg1Rc--\r\n\r\n.\r\n"

// const rawEmail string = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=proton.me;\r\n\ts=ueuj5vyzljhmhkiavspsghidca.protonmail; t=1705632616; x=1705891816;\r\n\tbh=nrIhwIHRqr4koq2DTGVOIiUukGd9u0FBuuv4XBW2Waw=;\r\n\th=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:\r\n\t Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector;\r\n\tb=XG9HaWPJGfTE1BCPSLU6ncuWl5H/mIwPH72qIFgQ2EXVHjyUr2iAsDLqemo9BBKGN\r\n\t ooTVdvmR36tDDhzMitLoI0tiGAWuzPv32qAeGTO9PbAMSYLkoxrRd4u/22IENJdbcN\r\n\t 4UIe0oprF6tAhMVVy6AEtXsu72l668Tu9jBDzIhnOq/BMQuHoPVgupaui4Blh2acos\r\n\t E2WPygU6rXo3M4Ec6D9WjxYFJW9YYuwupM/4H4RXglLpv1iiHKzvFU6uS1FwfuoDgI\r\n\t xmS3wjhom6u6gkVC6U6PwgbQGAYIdacVFHVngV1Xtds07RP88RmWc9jAyK1bKeTfbD\r\n\t gmITHqEY256Yg==\r\nDate: Fri, 19 Jan 2024 02:49:55 +0000\r\nTo: \"admin@llillii.li\" <admin@llillii.li>\r\nFrom: qugu2427 <qugu2427@proton.me>\r\nSubject: Test\r\nMessage-ID: <iTVXfR-IrsoLjU3Jb4l_Qg6EqNP0LvEx2_0f8uKXRnA9W6c7muJbJDGxAiBeYD0jy_fhXsbeUWmwD3xr3f8riXHc4iSq6dh2Xdl6ZYrhAQk=@proton.me>\r\nFeedback-ID: 85942582:user:proton\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n boundary=\"b1_DQh7FxANHlpime5X7zSNRDwdKhyKUoubwSzRzoSiso\"\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n--b1_DQh7FxANHlpime5X7zSNRDwdKhyKUoubwSzRzoSiso\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\neW8KCmhpCgp0ZXN0\r\n\r\n--b1_DQh7FxANHlpime5X7zSNRDwdKhyKUoubwSzRzoSiso\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0\r\ncHg7IGNvbG9yOiByZ2IoMCwgMCwgMCk7IGJhY2tncm91bmQtY29sb3I6IHJnYigyNTUsIDI1NSwg\r\nMjU1KTsiPnlvPC9kaXY+PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlm\r\nOyBmb250LXNpemU6IDE0cHg7IGNvbG9yOiByZ2IoMCwgMCwgMCk7IGJhY2tncm91bmQtY29sb3I6\r\nIHJnYigyNTUsIDI1NSwgMjU1KTsiPjxicj48L2Rpdj48ZGl2IHN0eWxlPSJmb250LWZhbWlseTog\r\nQXJpYWwsIHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTogMTRweDsgY29sb3I6IHJnYigwLCAwLCAwKTsg\r\nYmFja2dyb3VuZC1jb2xvcjogcmdiKDI1NSwgMjU1LCAyNTUpOyI+aGk8L2Rpdj48ZGl2IHN0eWxl\r\nPSJmb250LWZhbWlseTogQXJpYWwsIHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTogMTRweDsgY29sb3I6\r\nIHJnYigwLCAwLCAwKTsgYmFja2dyb3VuZC1jb2xvcjogcmdiKDI1NSwgMjU1LCAyNTUpOyI+PGJy\r\nPjwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtZmFtaWx5OiBBcmlhbCwgc2Fucy1zZXJpZjsgZm9udC1z\r\naXplOiAxNHB4OyBjb2xvcjogcmdiKDAsIDAsIDApOyBiYWNrZ3JvdW5kLWNvbG9yOiByZ2IoMjU1\r\nLCAyNTUsIDI1NSk7Ij50ZXN0PC9kaXY+PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBz\r\nYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7IGNvbG9yOiByZ2IoMCwgMCwgMCk7IGJhY2tncm91\r\nbmQtY29sb3I6IHJnYigyNTUsIDI1NSwgMjU1KTsiPjxicj48L2Rpdj4=\r\n\r\n\r\n--b1_DQh7FxANHlpime5X7zSNRDwdKhyKUoubwSzRzoSiso--\r\n\r\n.\r\n"

// const rawEmail string = "Received: by mail-oo1-f50.google.com with SMTP id 006d021491bc7-5990de0ea91so144289eaf.1\r\n        for <admin@llillii.li>; Thu, 18 Jan 2024 17:54:01 -0800 (PST)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=colorado.edu; s=google; t=1705629240; x=1706234040; darn=llillii.li;\r\n        h=to:subject:message-id:date:from:reply-to:mime-version:from:to:cc\r\n         :subject:date:message-id:reply-to;\r\n        bh=jP1F9E53yVoIDhhrJ8K+epL3IkWudjlv473/b2HRf1g=;\r\n        b=YGGF11DbsT2ZEA5VPpzHNom0IUrYfpeUUkqtu6ksKnWU2dGeFZ3ZS0jLdcfpWqqw3G\r\n         bC6bVrTNvYjVXqx00QQLXLt4deP3zGsr5kgEXRttS2QzOUalVMT4QXwsDV63z9lE9utv\r\n         kVC4KS3ToFkgdpO0jtM3sAeZaoCdpmZ5dlHFXs868DECW6s94cSxcWP+e0T119/WGFVh\r\n         eomvEXqbIRP8QN9e/3a8x1Y5bqr3IZ/I1PWHZyPIutZYX+h7VQyDYWN1HHlttur26UZb\r\n         Px9st/Wrr4ey9wEpOzKzbB03u3TkerttoLXQMrGSFrZzluq8IIqH3lTZjiP7kd8NRT13\r\n         yVyg==\r\nX-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20230601; t=1705629240; x=1706234040;\r\n        h=to:subject:message-id:date:from:reply-to:mime-version\r\n         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;\r\n        bh=jP1F9E53yVoIDhhrJ8K+epL3IkWudjlv473/b2HRf1g=;\r\n        b=ZahAdfzOVSjjlS1Grfsb9nv3hHrRBBTmPJGSFm9pRPTxJ7EpNkGwtVA7JAVwtPbpe4\r\n         NzXG0bQ0buoFKbWdEe0ISFscTf4urlc3WrAVHh1cH7otfnhWzHQTflc3bFJNXabXiHaZ\r\n         SGdWUPAfx+NFH6hSwWCoQMX7B/9TOo92kOJUnb5WgjiULLO/GLztvfWOeJfcfRZRjZZY\r\n         7JNX5h4dtGt67SWzt7PMN3GJ8b2bLFNiXmIFi2KOanl7f6DmqnLuqHAlYHRi0QXZhF4m\r\n         T4FWShVXmPbAavHYoSNAQC0j/+VGMZeTLf+4KkdWNaLmnYzI4ED95wI9mvpF4kVr78PA\r\n         ik9g==\r\nX-Gm-Message-State: AOJu0YzVwQvnpuIVXhBjTzRjbXNx0aAcS8jLB0Plmz7jgxEZv+dmnALF\r\n\tXHre6avt3O8isQNgM7uRnf4m116dtdCMfzbuQCnjXR+ieObK0uB6eRBdxtsq+7XcwU0rdszZN9k\r\n\tzMnSK1JmK/0UBqlnOMNvGJuX95dMuNDlS8Mbm0RUVwyKf/wc=\r\nX-Google-Smtp-Source: AGHT+IH3Z/9wst2tTl4iEu+NOU6OR5LRuMaByt+RgwaxRWAGiPp9+dJ5ZbSJTfNrPl5sNGVwa+7vKho/hjGOVBWGLkQ=\r\nX-Received: by 2002:a4a:a2c4:0:b0:599:4484:8f65 with SMTP id\r\n r4-20020a4aa2c4000000b0059944848f65mr1581759ool.15.1705629240549; Thu, 18 Jan\r\n 2024 17:54:00 -0800 (PST)\r\nMIME-Version: 1.0\r\nReply-To: Quinn.Guerin@colorado.edu\r\nFrom: Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nDate: Fri, 19 Jan 2024 01:53:50 +0000\r\nMessage-ID: <CAKDWnjea+F2CddKumhfuWZOesQsq6dgLuxEpwNnL1CZhR4ppWw@mail.gmail.com>\r\nSubject: dsf\r\nTo: admin@llillii.li\r\nContent-Type: multipart/alternative; boundary=\"00000000000000799a060f42c111\"\r\n\r\n--00000000000000799a060f42c111\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nsdfsdfsdfs\r\n\r\n--00000000000000799a060f42c111\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">sdfsdfsdfs<br></div>\r\n\r\n--00000000000000799a060f42c111--\r\n.\r\n"

func main() {
	// fmt.Println(rawEmail)

	// signPayload := SignPayload{
	// 	unsignedEmail,
	// 	"example.org",
	// 	"dkim",
	// 	[]string{"From", "To"},
	// 	nil,
	// }
	// signedEmail, err := signPayload.Sign()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("%#v\n", signedEmail)
	// fmt.Println(Verify(signedEmail))

	fmt.Println(Verify(rawEmail))

	// h, err := computeHash(RSASHA256, []byte("This is a test message.\r\n"))
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(base64.StdEncoding.EncodeToString(h))

	// bh, err := computeHash(RSASHA256, []byte("a-header:1.0\r\nb-header:abcD\t\nc-header:Some Thing\r\nfrom:John Doe <John.Doe@test.domain>\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.domain; h=a-header:b-header:c-header:from; s=dkim; bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; b=4Wq12AkqIfxE/fAGgoTdYjFW9dOVYEKd8c/LqdovFRg="))
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(base64.StdEncoding.EncodeToString(bh))

	// var testSigMsg = `date:Fri, 19 Jan 2024 02:44:51 +0000\r\nto:\"admin@llillii.li\" <admin@llillii.li>\r\nfrom:qugu2427 <qugu2427@proton.me>\r\nsubject:Test\r\nmessage-id:<DhrC06ISvjenM5t098NtiLKIHVRz8YNp_dGeBoNV9OBNOcRl_ZbKLbNUTwm_za05eHn35kZ7K3elYDnCd_fIurFK6ryYdK3z4EzM7H2bmKI=@proton.me>\r\nfeedback-id:85942582:user:proton\r\nfrom:qugu2427 <qugu2427@proton.me>\r\nto:\"admin@llillii.li\" <admin@llillii.li>\r\ncc:\r\ndate:Fri, 19 Jan 2024 02:44:51 +0000\r\nsubject:Test\r\nreply-to:\r\nfeedback-id:85942582:user:proton\r\nmessage-id:<DhrC06ISvjenM5t098NtiLKIHVRz8YNp_dGeBoNV9OBNOcRl_ZbKLbNUTwm_za05eHn35kZ7K3elYDnCd_fIurFK6ryYdK3z4EzM7H2bmKI=@proton.me>\r\nbimi-selector:\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=proton.me;\ts=protonmail; t=1705632310; x=1705891510;\tbh=bgiK6lNfK6S+lYdqzqW4CXkAgkNAZMNne+zmC2MmpI8=;\th=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date: Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector;\tb=\r\n`

	// pubKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn46zCm3zHBmS1zePKxA+RIXw41Nu6l91NpLLBnWnrcZ35H/843XNWPZEQ0OgGwx/yqTXETMLXIDjGEWlK1E1mpdguqu+3s7SuIHoo5+i6mgyxJguljkwc3dk8ojnJ6VVUPnDh5GJArkAhXxEb1aOK1BVGM0yDlmYdmaOfd48qcx5iODP/MFc8pivfxEXTIL+aUz7+X69lMiwUSHpWYL3/a5X3nLD0zEntxv08xs8J/rpuRg4v+OXEOhcNvhkeiRZqJBdpJTkoEZfGvdTct+U0YYC69NW0ClUcKio2uDPmxU1xvfvHbSTW2gHYk8RpYZaxLACULdMo+Vt4Na/oIR+swIDAQAB\n-----END PUBLIC KEY-----"
	// sig, _ := base64.StdEncoding.DecodeString("gkQXpOyER5R8Y2XR+H5jmOeSFaP4ZqNFk5qRFFMBLc0RPr7ihdx1Q4ehTWhLITazz")

	// err := checkSignature(
	// 	RSASHA256,
	// 	RSA,
	// 	pubKey,
	// 	[]byte(testSigMsg),
	// 	sig,
	// )
	// fmt.Println(err)

	// extractSignatureMessage(Simple, rawEmail)

	// fmt.Printf("--------------------\nRESULT: %#v\n--------------------\n", VerifyEmail(rawEmail))

	// dkimHeader, err := extractDKIMHeader(rawEmail)
	// if err != nil {
	// 	panic(err)
	// }
	// dkimRecord, err := fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
	// if err != nil {
	// 	panic(err)
	// }

	// canonHeaders, canonBody, err := CanonicalizeEmail(dkimHeader.c, rawEmail)
	// if err != nil {
	// 	panic(err)
	// }

	// err = dkimHeader.VerifyBodyHash(canonBody)
	// if err != nil {
	// 	panic(err)
	// }

	// sigMsg, err := buildSignatureMessage(&dkimHeader, canonHeaders, dkimHeader.c.headerCanon)
	// if err != nil {
	// 	panic(err)
	// }
	// // sigMsg = "to:admin@llillii.li\r\nsubject:fwe\r\nmessage-id:<CAKDWnjcP=VPDcRZ_BS_J6QSg01nF-7gwUevNz7mNP6Hremb3NA@mail.gmail.com>\r\ndate:Mon, 15 Jan 2024 23:15:58 +0000\r\nfrom:Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nreply-to:Quinn.Guerin@colorado.edu\r\nmime-version:1.0\r\nfrom:Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nto:admin@llillii.li\r\ncc:\r\nsubject:fwe\r\ndate:Mon, 15 Jan 2024 23:15:58 +0000\r\nmessage-id:<CAKDWnjcP=VPDcRZ_BS_J6QSg01nF-7gwUevNz7mNP6Hremb3NA@mail.gmail.com>\r\nreply-to:Quinn.Guerin@colorado.edu\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=colorado.edu; s=google; t=1705360569; x=1705965369; darn=llillii.li; bh=tfDE7NK8oIhTax07knTNmwC8mQFtGDhL/Zt6ZU9sOLs=; b="
	// // sigMsg += canonBody
	// // sigMsg = "to:admin@llillii.li\r\nsubject:fwe\r\nmessage-id:<CAKDWnjcP=VPDcRZ_BS_J6QSg01nF-7gwUevNz7mNP6Hremb3NA@mail.gmail.com>\r\ndate:Mon, 15 Jan 2024 23:15:58 +0000\r\nfrom:Quinn Guerin <Quinn.Guerin@colorado.edu>\r\nreply-to:Quinn.Guerin@colorado.edu\r\nmime-version:1.0\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=colorado.edu; s=google; t=1705360569; x=1705965369; darn=llillii.li; h=to:subject:message-id:date:from:reply-to:mime-version:from:to:cc :subject:date:message-id:reply-to; bh=tfDE7NK8oIhTax07knTNmwC8mQFtGDhL/Zt6ZU9sOLs=; b="

	// fmt.Printf("%#v\n", dkimHeader.h)
	// fmt.Printf("%#v\n", sigMsg)

	// err = checkSignature(dkimHeader.a, dkimRecord.k, dkimRecord.p, sigMsg, dkimHeader.b)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("HOLY FUCKING SHIT IT VERIFIED")
}
