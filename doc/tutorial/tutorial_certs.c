const char* CA_CERTIFICATE =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICWTCCAbugAwIBAgIJAM2Bv4myXxmmMAoGCCqGSM49BAMCMEQxCzAJBgNVBAYT\r\n"
    "AlVTMQwwCgYDVQQKDANEUFMxJzAlBgNVBAMMHlR1dG9yaWFsIENlcnRpZmljYXRl\r\n"
    "IEF1dGhvcml0eTAeFw0xODAyMjgxNjM5NDBaFw0yODAyMjYxNjM5NDBaMEQxCzAJ\r\n"
    "BgNVBAYTAlVTMQwwCgYDVQQKDANEUFMxJzAlBgNVBAMMHlR1dG9yaWFsIENlcnRp\r\n"
    "ZmljYXRlIEF1dGhvcml0eTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAO91V2b6\r\n"
    "EHEBXANTeuSvG7p7ChQxzpDj7Rm01Ml6pftU1qhu2R00++7laL2SXHLJ7m2DTreZ\r\n"
    "Wfp1N8habyX+etohAFnN8wX3a8G5jGBG1SqGBWR7koakg2DqVOcUAa/A9Vr1lIh/\r\n"
    "1m3AhJnYFcd/gpEfO9ykw5fsShN2KsFrcz4EMOGko1MwUTAdBgNVHQ4EFgQUYSPr\r\n"
    "6BW5frjDRq9cZCm5QsikbagwHwYDVR0jBBgwFoAUYSPr6BW5frjDRq9cZCm5Qsik\r\n"
    "bagwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgOBiwAwgYcCQgDJcCc+Tyjz\r\n"
    "SaHE1mMamSAeY/nTWXvlpcMNZLawm1PEBlQbPXU/v1FzEJhfyyP4eiQQnTT7/IlE\r\n"
    "h1h9o1qr2tJXIgJBNEViLe6NwrijEsB5acHKsWNEbKXireZuMN96cjDBJ3U94S1G\r\n"
    "4H8kTpbXK12qAj6l00VsCUb0IGLl86k4dSEjong=\r\n"
    "-----END CERTIFICATE-----\r\n";
const Certificate CERTIFICATES[] = {
    {
        BYTE_STR("Tutorial Publisher Node"),
        {
            DPS_KEY_EC_CERT,
            {
                .cert = {
                    "-----BEGIN CERTIFICATE-----\r\n"
                    "MIIB+TCCAVoCCQCZlPbjq+6vTDAKBggqhkjOPQQDBDBEMQswCQYDVQQGEwJVUzEM\r\n"
                    "MAoGA1UECgwDRFBTMScwJQYDVQQDDB5UdXRvcmlhbCBDZXJ0aWZpY2F0ZSBBdXRo\r\n"
                    "b3JpdHkwHhcNMTgwMjI4MTYzOTQwWhcNMjgwMjI2MTYzOTQwWjA9MQswCQYDVQQG\r\n"
                    "EwJVUzEMMAoGA1UECgwDRFBTMSAwHgYDVQQDDBdUdXRvcmlhbCBQdWJsaXNoZXIg\r\n"
                    "Tm9kZTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEATTQw5vkjNGW+QbLcFO5EJkN\r\n"
                    "RzOmyR0IEA5KEZJKd3U6V3nsKDQwCV9t2n4pTGtpIYslIFA32tTUl3A+TQQeoZ8s\r\n"
                    "ARvr3A60mT0M4XOMgFQ064ZaQOvHrraI/leji96M7E+SCTGgl81JqZGRkcKb2E3w\r\n"
                    "gz99t8seSOFKYviCIWVsPOBOMAoGCCqGSM49BAMEA4GMADCBiAJCAY0beVl+J0rc\r\n"
                    "GF84CNzN4H9MNfydIbC2V2l4WU9dy+Vn2C/GhrfPiF5zCu+X3T0AYaZf1jZ0NWur\r\n"
                    "n0ikEiKXvMDMAkIBlTwMKxA4DY6anwm0YgnsQdfXJQ4Mg7a57CghFLbtgSw9qkoN\r\n"
                    "4/qE/M0hY59wZ2RYsyx8LMeRxRod5jHe+CVqqGU=\r\n"
                    "-----END CERTIFICATE-----\r\n",
                    "-----BEGIN EC PRIVATE KEY-----\r\n"
                    "Proc-Type: 4,ENCRYPTED\r\n"
                    "DEK-Info: AES-256-CBC,2BD663A0EFBAEC2C6724EAEADBD6E504\r\n"
                    "\r\n"
                    "B1pRO6wpv2x6ohxotwdYH3PWmsZSDjqDFP6WGZ9+skrGaMktM7fwuR6W4M/gsal5\r\n"
                    "VgQsXlbfxkRQ9yx+kUlK9baLlnDl/2PzrCAONet3KBlPt19UYr1UP8IrrgL1P5r4\r\n"
                    "SoMFf/1zwWYfyz3iTYNugESPYv/qyeWe4bXLIkgxphjMn/MaGU5NXWach/JJExuP\r\n"
                    "fy6fcmjOFtH9K3wrUIMgV2arC7XSXpG2xSYiBXrdHyphfFx+0//TacIks6vK5TvU\r\n"
                    "0+x2bt26XwJSDcpuApNkjNSErN+3pCu4Ke9QJRtDUWI=\r\n"
                    "-----END EC PRIVATE KEY-----\r\n",
                    "Tutorial Publisher Node Password"
                }
            }
        }
    },
    {
        BYTE_STR("Tutorial Subscriber Node"),
        {
            DPS_KEY_EC_CERT,
            {
                .cert = {
                    "-----BEGIN CERTIFICATE-----\r\n"
                    "MIIB+jCCAVsCCQCZlPbjq+6vTTAKBggqhkjOPQQDBDBEMQswCQYDVQQGEwJVUzEM\r\n"
                    "MAoGA1UECgwDRFBTMScwJQYDVQQDDB5UdXRvcmlhbCBDZXJ0aWZpY2F0ZSBBdXRo\r\n"
                    "b3JpdHkwHhcNMTgwMjI4MTYzOTQwWhcNMjgwMjI2MTYzOTQwWjA+MQswCQYDVQQG\r\n"
                    "EwJVUzEMMAoGA1UECgwDRFBTMSEwHwYDVQQDDBhUdXRvcmlhbCBTdWJzY3JpYmVy\r\n"
                    "IE5vZGUwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHex5Aoos1j5KoYl02Pzf5I\r\n"
                    "4CCpD9dquiOupwQ1W+YBwOtk5LEq/qpq0n4HkDDc6+AkKePHWv9QI7q7uR4mSl0J\r\n"
                    "QAEXGZAyNxYcCYks3Nw1ie9ShlWkBQjRCHXvvPlKiZqt1aPg+jk2elNk5z/bDwF4\r\n"
                    "4rH0NA4UTQ1xzq+9I3R1KASe9TAKBggqhkjOPQQDBAOBjAAwgYgCQgDeWSGKfwbf\r\n"
                    "QOiM2xCEhBy97w1d86mNYYl8lJqUqDirNZxaluOFrFTQ1cIRDvIyN9OQcmY4iaLS\r\n"
                    "dlKbybFUtK3ngQJCAXxNu9jJeW55bdv1sRlP1AuRLaWza2ME2Dyc5U8R8WL/czpW\r\n"
                    "otvMaP3dfOgznmC+83Re5NKAqXxBedQcbQs8iaqO\r\n"
                    "-----END CERTIFICATE-----\r\n",
                    "-----BEGIN EC PRIVATE KEY-----\r\n"
                    "Proc-Type: 4,ENCRYPTED\r\n"
                    "DEK-Info: AES-256-CBC,D13CB14FFFDECBE4C438D46E197E82FE\r\n"
                    "\r\n"
                    "aZ6/IxTCGp/imB4kMu6HhwRwgfbfhGj5v0wKFjFmR+paCbWwV3A1nJEDJsmeOLFy\r\n"
                    "5ku4fDK8qDAzfBKYecHV5gpQOIdqGPNUP10DgWD3yuGB7JfrLBm4QznOIzD1HXdZ\r\n"
                    "DSnaoLtnL8emIpBShq7FgR/tCwagJ/4LDn8weKbLHS0w+2KnU3rRSiODMFcYak3f\r\n"
                    "msoE93Nshes7ymD9OiXjCYA/uXkxuaHu/KDpmZHVFirhm6PlrB+BzlAo8REnLsHN\r\n"
                    "oqhqHDKlrBlPa2aQo1pjNDBvWi/yMcgiVAyB4+Sw4as=\r\n"
                    "-----END EC PRIVATE KEY-----\r\n",
                    "Tutorial Subscriber Node Password"
                }
            }
        }
    },
    {
        BYTE_STR("Tutorial Node"),
        {
            DPS_KEY_EC_CERT,
            {
                .cert = {
                    "-----BEGIN CERTIFICATE-----\r\n"
                    "MIIB7zCCAVACCQCZlPbjq+6vTjAKBggqhkjOPQQDBDBEMQswCQYDVQQGEwJVUzEM\r\n"
                    "MAoGA1UECgwDRFBTMScwJQYDVQQDDB5UdXRvcmlhbCBDZXJ0aWZpY2F0ZSBBdXRo\r\n"
                    "b3JpdHkwHhcNMTgwMjI4MTYzOTQwWhcNMjgwMjI2MTYzOTQwWjAzMQswCQYDVQQG\r\n"
                    "EwJVUzEMMAoGA1UECgwDRFBTMRYwFAYDVQQDDA1UdXRvcmlhbCBOb2RlMIGbMBAG\r\n"
                    "ByqGSM49AgEGBSuBBAAjA4GGAAQBCVfiG/MRTk7ViPx54W9n4ieWayNtz2I1sndJ\r\n"
                    "D08wJQ1vXGcodpuIlKumwuQ2j6IBb9ur9hIYcBvXT47kbjS0n/0AhOgD7LRzuJLf\r\n"
                    "7UZ1EwSOnegH6EKZgt3mHARtTmcAJMBZ5WY5mfncriKvl4744bxuxE+dOOF3wo0Y\r\n"
                    "SFywTT5XWu4wCgYIKoZIzj0EAwQDgYwAMIGIAkIBukDQ0XNYk73Ut9kxJrN9eT9B\r\n"
                    "ZMdnKv91K9sAwRGq3V9Pb8uz1Kb/lt839PSaiDTkjJpr6jYsAf9TPaRkIw/wQMYC\r\n"
                    "QgFqyGzK81QKxalAq90WKwPpCRvnBgPwWEXrf21b45uIGspS1lc/ow8RFsOFjBrT\r\n"
                    "VpMj6uWvPXhzwvMMZxYuJnUs/w==\r\n"
                    "-----END CERTIFICATE-----\r\n",
                    "-----BEGIN EC PRIVATE KEY-----\r\n"
                    "Proc-Type: 4,ENCRYPTED\r\n"
                    "DEK-Info: AES-256-CBC,0F634AC006810F275C51587945BECC21\r\n"
                    "\r\n"
                    "MBlcQ338a+3a3LC7s6KGDsYkQCRZNN6+4a6/omsAQjvTN2G6X691QvupCn8emzX1\r\n"
                    "5mqAejTNGMO9PqCqX7jq+8K0AT4nnDaEfxLQljzZodSE/3Az9al6+DGrVXA5tCCd\r\n"
                    "ZP4edAmGuuTqlF7TJW8o7vfU0KBfeyBU3gSo8yvt2Gt+9JwqZV6gWITdBDtyarvD\r\n"
                    "zi5wU3C7v1mAnfYxPRkdIZ/mkEJhoMFpw7gHjgSCWCQusE9541BwEpAQUrIiS+Bk\r\n"
                    "HYgQ2El5Urx94nigEhvXhC+TTALDdmZ+Oi7cf7CrCb0=\r\n"
                    "-----END EC PRIVATE KEY-----\r\n",
                    "Tutorial Node Password"
                }
            }
        }
    },
    {
        { NULL, 0 }, { DPS_KEY_EC_CERT, { .cert = { NULL, NULL, NULL } } }
    }
};
const DPS_Key ASYMMETRIC_KEY = {
    DPS_KEY_EC_CERT,
    {
        .cert = {
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIB+TCCAVoCCQCZlPbjq+6vTzAKBggqhkjOPQQDBDBEMQswCQYDVQQGEwJVUzEM\r\n"
            "MAoGA1UECgwDRFBTMScwJQYDVQQDDB5UdXRvcmlhbCBDZXJ0aWZpY2F0ZSBBdXRo\r\n"
            "b3JpdHkwHhcNMTgwMjI4MTYzOTQwWhcNMjgwMjI2MTYzOTQwWjA9MQswCQYDVQQG\r\n"
            "EwJVUzEMMAoGA1UECgwDRFBTMSAwHgYDVQQDDBdUdXRvcmlhbCBBc3ltbWV0cmlj\r\n"
            "IEtleTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAHCLWOOMbnCeR+XgrBuINpMC\r\n"
            "07nabRFvSDThM6bgvhZGpkpZzg9NYBlhQVtplvTsX/AADgTV12vSOB1PPJVbkmkE\r\n"
            "AJjGpVdhOFEDORsjZCed+X+0mkYbMShjVDdKbG71I7FjckhohfSFOXKE8n5TXiBb\r\n"
            "L44ZUbmKxydnHPjCE8HQe7pTMAoGCCqGSM49BAMEA4GMADCBiAJCAZQHaW8Ivs1I\r\n"
            "xHxOxC+/oHvbK7vP1lQR0ttx7hKqSj17syByfqrpfPo0NUO/qJ8jjAfyM84EHnnJ\r\n"
            "6AqvF+naU23BAkIBGlVN+heRfifdmiSIIZSHIlysVNX3toIMCkD3+IapeWbSybPx\r\n"
            "DzCeoy2HL7oO54YindL1r5Y5eFsVYdyr/Y6HkMw=\r\n"
            "-----END CERTIFICATE-----\r\n",
            "-----BEGIN EC PRIVATE KEY-----\r\n"
            "Proc-Type: 4,ENCRYPTED\r\n"
            "DEK-Info: AES-256-CBC,E3AAC7889B8D188C63EBB02D47DB0A30\r\n"
            "\r\n"
            "LO3exjKL3Rn/7ggLH0l/2MLtvQScjeixyfP+JXyXmKe5WYoevfheLdq6sQp0v7qi\r\n"
            "kilNnwCwF//LIHR6d9rjOP/qnnbeGtApnFtJP0/rWTsz3LzIozFY8oXIy6BeC9F4\r\n"
            "1CUWnZxn48+TU2prH2/WPTIi2wREuSAhA2haZoTCwuKxT22JBz8PPbTMGW/L+7xF\r\n"
            "UN+ZvLX0dNtZfPWMnCQzIICMJTeALMN1YQ7NaignxDLRDc+pviiwlJwngkRIH5R2\r\n"
            "iCeI6xD/AUbQWl+zGBRlTPKljU3YQGqqO79I3yC6wg0=\r\n"
            "-----END EC PRIVATE KEY-----\r\n",
            "Tutorial Asymmetric Key Password"
        }
    }
};
