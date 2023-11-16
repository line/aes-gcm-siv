/*
 * Copyright 2023 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "gtest/gtest.h"

#include "utils.h"

#include "aes_gcmsiv.h"

// KAT from RFC-8452 (https://datatracker.ietf.org/doc/html/rfc8452)

TEST(KAT, Encrypt128)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "dc20e2d83f25705bb49e439eca56de25",
        },
        {
            "0100000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "b5d839330ac7b786578782fff6013b815b287c22493a364c",
        },
        {
            "010000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639",
        },
        {
            "01000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a9445"
            "1a8e45dcd4578c667cd86847bf6155ff",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "03000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64d"
            "f42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "0300000000000000000000000000000004000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af0"
            "2516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f"
            "8a263dd317aa88d56bdf3936dba75bb8",
        },
        {
            "0200000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508",
        },
        {
            "020000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a",
        },
        {
            "02000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71"
            "e6af6a7f87287da059a71684ed3498e1",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "04000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b005"
            "3201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "0400000000000000000000000000000005000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42fe"
            "ec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80"
            "cdc46ae475563de037001ef84ae21744",
        },
        {
            "02000000",
            "010000000000000000000000",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14",
        },
        {
            "0300000000000000000000000000000004000000",
            "010000000000000000000000000000000200",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6"
            "fe106514",
        },
        {
            "030000000000000000000000000000000400",
            "0100000000000000000000000000000002000000",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13"
            "b9fd",
        },
        {
            "",
            "",
            "e66021d5eb8e4f4066d4adb9c33560e4",
            "f46e44bb3da0015c94f70887",
            "a4194b79071b01a87d65f706e3949578",
        },
        {
            "7a806c",
            "46bb91c3c5",
            "36864200e0eaf5284d884a0e77d31646",
            "bae8e37fc83441b16034566b",
            "af60eb711bd85bc1e4d3e0a462e074eea428a8",
        },
        {
            "bdc66f146545",
            "fc880c94a95198874296",
            "aedb64a6c590bc84d1a5e269e4b47801",
            "afc0577e34699b9e671fdd4f",
            "bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966",
        },
        {
            "1177441f195495860f",
            "046787f3ea22c127aaf195d1894728",
            "d5cc1fd161320b6920ce07787f86743b",
            "275d1ab32f6d1f0434d8848c",
            "4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b",
        },
        {
            "9f572c614b4745914474e7c7",
            "c9882e5386fd9f92ec489c8fde2be2cf97e74e93",
            "b3fed1473c528b8426a582995929a149",
            "9e9ad8780c8d63d0ab4149c0",
            "f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0",
        },
        {
            "0d8c8451178082355c9e940fea2f58",
            "2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a",
            "2d4ed87da44102952ef94b02b805249b",
            "ac80e6f61455bfac8308a2d4",
            "c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b",
        },
        {
            "6b3db4da3d57aa94842b9803a96e07fb6de7",
            "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f",
            "bde3b2f204d1e9f8b06bc47f9745b3d1",
            "ae06556fb6aa7890bebc18fe",
            "6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4"
            "db84",
        },
        {
            "e42a3c02c25b64869e146d7b233987bddfc240871d",
            "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa"
            "859c21",
            "f901cfe8a69615a93fdf7a98cad48179",
            "6245709fb18853f68d833640",
            "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9"
            "d24a2a6e70",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto plain = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto expected = from_hex(test[4]);
        uint8_t *cipher = nullptr;
        size_t cipher_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_encrypt_size(plain.size(), aad.size(), &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(cipher_sz, expected.size());

        // Allocate space for ciphertext
        cipher = new uint8_t[cipher_sz];
        ASSERT_NE(cipher, nullptr);

        // Perform encryption
        ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce.data(), nonce.size(), plain.data(),
                                          plain.size(), aad.data(), aad.size(), cipher, cipher_sz,
                                          &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(cipher, cipher_sz, expected.data(), expected.size()));

        aes_gcmsiv_free(&ctx);
        delete[] cipher;
    }
}

TEST(KAT, Encrypt256)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "07f5f4169bbf55a8400cd47ea6fd400f",
        },
        {
            "0100000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        },
        {
            "010000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        },
        {
            "01000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f"
            "e819e63abcd020b006a976397632eb5d",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "03000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3"
            "9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "0300000000000000000000000000000004000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7"
            "e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce"
            "112864c269fc0d9d88c61fa47e39aa08",
        },
        {
            "0200000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        },
        {
            "020000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
        },
        {
            "02000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365"
            "aea1bad12702e1965604374aab96dbbc",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "04000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47"
            "fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "0400000000000000000000000000000005000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9"
            "8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89"
            "5bde0285037c5de81e5b570a049b62a0",
        },
        {
            "02000000",
            "010000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "22b3f4cd1835e517741dfddccfa07fa4661b74cf",
        },
        {
            "0300000000000000000000000000000004000000",
            "010000000000000000000000000000000200",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59"
            "cabfe307",
        },
        {
            "030000000000000000000000000000000400",
            "0100000000000000000000000000000002000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc205"
            "6543",
        },
        {
            "",
            "",
            "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
            "e0eaf5284d884a0e77d31646",
            "169fbb2fbf389a995f6390af22228a62",
        },
        {
            "671fdd",
            "4fbdc66f14",
            "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
            "e4b47801afc0577e34699b9e",
            "0eaccb93da9bb81333aee0c785b240d319719d",
        },
        {
            "195495860f04",
            "6787f3ea22c127aaf195",
            "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
            "2f6d1f0434d8848c1177441f",
            "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c",
        },
        {
            "c9882e5386fd9f92ec",
            "489c8fde2be2cf97e74e932d4ed87d",
            "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
            "9f572c614b4745914474e7c7",
            "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2",
        },
        {
            "1db2316fd568378da107b52b",
            "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
            "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
            "5c9e940fea2f582950a70d5a",
            "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5",
        },
        {
            "21702de0de18baa9c9596291b08466",
            "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
            "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
            "6de71860f762ebfbd08284e4",
            "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
        },
        {
            "b202b370ef9768ec6561c4fe6b7e7296fa85",
            "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
            "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
            "028ec6eb5ea7e298342a94d4",
            "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d"
            "0a49",
        },
        {
            "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
            "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f"
            "167541",
            "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
            "688089e55540db1872504e1c",
            "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1d"
            "ed1a286594",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto plain = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto expected = from_hex(test[4]);
        uint8_t *cipher = nullptr;
        size_t cipher_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_encrypt_size(plain.size(), aad.size(), &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(cipher_sz, expected.size());

        // Allocate space for ciphertext
        cipher = new uint8_t[cipher_sz];
        ASSERT_NE(cipher, nullptr);

        // Perform encryption
        ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce.data(), nonce.size(), plain.data(),
                                          plain.size(), aad.data(), aad.size(), cipher, cipher_sz,
                                          &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(cipher, cipher_sz, expected.data(), expected.size()));

        aes_gcmsiv_free(&ctx);
        delete[] cipher;
    }
}

TEST(KAT, Decrypt128)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "dc20e2d83f25705bb49e439eca56de25",
        },
        {
            "0100000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "b5d839330ac7b786578782fff6013b815b287c22493a364c",
        },
        {
            "010000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639",
        },
        {
            "01000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a9445"
            "1a8e45dcd4578c667cd86847bf6155ff",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "03000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64d"
            "f42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "0300000000000000000000000000000004000000000000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af0"
            "2516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f"
            "8a263dd317aa88d56bdf3936dba75bb8",
        },
        {
            "0200000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508",
        },
        {
            "020000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a",
        },
        {
            "02000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71"
            "e6af6a7f87287da059a71684ed3498e1",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "04000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b005"
            "3201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "0400000000000000000000000000000005000000000000000000000000000000",
            "01",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42fe"
            "ec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80"
            "cdc46ae475563de037001ef84ae21744",
        },
        {
            "02000000",
            "010000000000000000000000",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14",
        },
        {
            "0300000000000000000000000000000004000000",
            "010000000000000000000000000000000200",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6"
            "fe106514",
        },
        {
            "030000000000000000000000000000000400",
            "0100000000000000000000000000000002000000",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13"
            "b9fd",
        },
        {
            "",
            "",
            "e66021d5eb8e4f4066d4adb9c33560e4",
            "f46e44bb3da0015c94f70887",
            "a4194b79071b01a87d65f706e3949578",
        },
        {
            "7a806c",
            "46bb91c3c5",
            "36864200e0eaf5284d884a0e77d31646",
            "bae8e37fc83441b16034566b",
            "af60eb711bd85bc1e4d3e0a462e074eea428a8",
        },
        {
            "bdc66f146545",
            "fc880c94a95198874296",
            "aedb64a6c590bc84d1a5e269e4b47801",
            "afc0577e34699b9e671fdd4f",
            "bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966",
        },
        {
            "1177441f195495860f",
            "046787f3ea22c127aaf195d1894728",
            "d5cc1fd161320b6920ce07787f86743b",
            "275d1ab32f6d1f0434d8848c",
            "4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b",
        },
        {
            "9f572c614b4745914474e7c7",
            "c9882e5386fd9f92ec489c8fde2be2cf97e74e93",
            "b3fed1473c528b8426a582995929a149",
            "9e9ad8780c8d63d0ab4149c0",
            "f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0",
        },
        {
            "0d8c8451178082355c9e940fea2f58",
            "2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a",
            "2d4ed87da44102952ef94b02b805249b",
            "ac80e6f61455bfac8308a2d4",
            "c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b",
        },
        {
            "6b3db4da3d57aa94842b9803a96e07fb6de7",
            "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f",
            "bde3b2f204d1e9f8b06bc47f9745b3d1",
            "ae06556fb6aa7890bebc18fe",
            "6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4"
            "db84",
        },
        {
            "e42a3c02c25b64869e146d7b233987bddfc240871d",
            "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa"
            "859c21",
            "f901cfe8a69615a93fdf7a98cad48179",
            "6245709fb18853f68d833640",
            "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9"
            "d24a2a6e70",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto expected = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto cipher = from_hex(test[4]);
        uint8_t *plain = nullptr;
        size_t plain_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_decrypt_size(cipher.size(), aad.size(), &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(plain_sz, expected.size());

        // Allocate space for plaintext
        plain = new uint8_t[plain_sz];
        if (plain_sz > 0) {
            ASSERT_NE(plain, nullptr);
        }

        // Perform decryption
        ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce.data(), nonce.size(), cipher.data(),
                                           cipher.size(), aad.data(), aad.size(), plain, plain_sz,
                                           &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(plain, plain_sz, expected.data(), expected.size()));

        delete[] plain;

        aes_gcmsiv_free(&ctx);
    }
}

TEST(KAT, Decrypt256)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "07f5f4169bbf55a8400cd47ea6fd400f",
        },
        {
            "0100000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        },
        {
            "010000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        },
        {
            "01000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f"
            "e819e63abcd020b006a976397632eb5d",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "03000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3"
            "9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
        },
        {
            "0100000000000000000000000000000002000000000000000000000000000000"
            "0300000000000000000000000000000004000000000000000000000000000000",
            "",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7"
            "e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce"
            "112864c269fc0d9d88c61fa47e39aa08",
        },
        {
            "0200000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        },
        {
            "020000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
        },
        {
            "02000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365"
            "aea1bad12702e1965604374aab96dbbc",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "04000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47"
            "fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb",
        },
        {
            "0200000000000000000000000000000003000000000000000000000000000000"
            "0400000000000000000000000000000005000000000000000000000000000000",
            "01",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9"
            "8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89"
            "5bde0285037c5de81e5b570a049b62a0",
        },
        {
            "02000000",
            "010000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "22b3f4cd1835e517741dfddccfa07fa4661b74cf",
        },
        {
            "0300000000000000000000000000000004000000",
            "010000000000000000000000000000000200",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59"
            "cabfe307",
        },
        {
            "030000000000000000000000000000000400",
            "0100000000000000000000000000000002000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc205"
            "6543",
        },
        {
            "",
            "",
            "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
            "e0eaf5284d884a0e77d31646",
            "169fbb2fbf389a995f6390af22228a62",
        },
        {
            "671fdd",
            "4fbdc66f14",
            "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
            "e4b47801afc0577e34699b9e",
            "0eaccb93da9bb81333aee0c785b240d319719d",
        },
        {
            "195495860f04",
            "6787f3ea22c127aaf195",
            "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
            "2f6d1f0434d8848c1177441f",
            "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c",
        },
        {
            "c9882e5386fd9f92ec",
            "489c8fde2be2cf97e74e932d4ed87d",
            "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
            "9f572c614b4745914474e7c7",
            "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2",
        },
        {
            "1db2316fd568378da107b52b",
            "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
            "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
            "5c9e940fea2f582950a70d5a",
            "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5",
        },
        {
            "21702de0de18baa9c9596291b08466",
            "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
            "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
            "6de71860f762ebfbd08284e4",
            "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
        },
        {
            "b202b370ef9768ec6561c4fe6b7e7296fa85",
            "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
            "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
            "028ec6eb5ea7e298342a94d4",
            "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d"
            "0a49",
        },
        {
            "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
            "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f"
            "167541",
            "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
            "688089e55540db1872504e1c",
            "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1d"
            "ed1a286594",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto expected = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto cipher = from_hex(test[4]);
        uint8_t *plain = nullptr;
        size_t plain_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_decrypt_size(cipher.size(), aad.size(), &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(plain_sz, expected.size());

        // Allocate space for plaintext
        plain = new uint8_t[plain_sz];
        if (plain_sz > 0) {
            ASSERT_NE(plain, nullptr);
        }

        // Perform decryption
        ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce.data(), nonce.size(), cipher.data(),
                                           cipher.size(), aad.data(), aad.size(), plain, plain_sz,
                                           &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(plain, plain_sz, expected.data(), expected.size()));

        delete[] plain;

        aes_gcmsiv_free(&ctx);
    }
}

TEST(KAT, CounterWrapEncrypt)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea"
            "ffffffff000000000000000000000000",
        },
        {
            "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff00000000"
            "0000000000000000",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto plain = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto expected = from_hex(test[4]);
        uint8_t *cipher = nullptr;
        size_t cipher_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_encrypt_size(plain.size(), aad.size(), &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(cipher_sz, expected.size());

        // Allocate space for ciphertext
        cipher = new uint8_t[cipher_sz];
        ASSERT_NE(cipher, nullptr);

        // Perform encryption
        ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce.data(), nonce.size(), plain.data(),
                                          plain.size(), aad.data(), aad.size(), cipher, cipher_sz,
                                          &cipher_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(cipher, cipher_sz, expected.data(), expected.size()));

        aes_gcmsiv_free(&ctx);
        delete[] cipher;
    }
}

TEST(KAT, CounterWrapDecrypt)
{
    std::vector<std::vector<std::string>> tests = {
        {
            "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea"
            "ffffffff000000000000000000000000",
        },
        {
            "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff00000000"
            "0000000000000000",
        },
    };

    for (auto test : tests) {
        aes_gcmsiv_status_t ret;
        struct aes_gcmsiv_ctx ctx;
        auto expected = from_hex(test[0]);
        auto aad = from_hex(test[1]);
        auto key = from_hex(test[2]);
        auto nonce = from_hex(test[3]);
        auto cipher = from_hex(test[4]);
        uint8_t *plain = nullptr;
        size_t plain_sz = 0;

        // Init context
        aes_gcmsiv_init(&ctx);

        ret = aes_gcmsiv_set_key(&ctx, key.data(), key.size());
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

        // Query to have needed size
        ret = aes_gcmsiv_decrypt_size(cipher.size(), aad.size(), &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_EQ(plain_sz, expected.size());

        // Allocate space for plaintext
        plain = new uint8_t[plain_sz];
        if (plain_sz > 0) {
            ASSERT_NE(plain, nullptr);
        }

        // Perform decryption
        ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce.data(), nonce.size(), cipher.data(),
                                           cipher.size(), aad.data(), aad.size(), plain, plain_sz,
                                           &plain_sz);
        EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
        EXPECT_TRUE(memeq(plain, plain_sz, expected.data(), expected.size()));

        delete[] plain;

        aes_gcmsiv_free(&ctx);
    }
}
