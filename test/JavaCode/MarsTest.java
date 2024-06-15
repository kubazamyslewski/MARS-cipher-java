package JavaCode;

import static org.junit.jupiter.api.Assertions.*;

class MarsTest {

    @org.junit.jupiter.api.Test
    void encrypt() {
        //KEYSIZE=128
        String sPT = "00000000000000000000000000000000";
        String sKEY = "00000000000000000000000000000000";
        String sCheck = "DCC07B8DFB0738D6E30A22DFCF27E886";
        byte[] PT = Mars.hexStringToByteArray(sPT);
        byte[] key = Mars.hexStringToByteArray(sKEY);
        byte[] out;

        out = Mars.encrypt(PT, key);
        String encrypted = Mars.bytesToHex(out);
        assertEquals(encrypted, sCheck);

        sPT = "DCC07B8DFB0738D6E30A22DFCF27E886";
        sKEY = "00000000000000000000000000000000";
        sCheck = "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);


        sPT = "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF";
        sKEY = "00000000000000000000000000000000";
        sCheck = "62D0D531FD18BAC77177CEB2395EF18F";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);


        sPT = "62D0D531FD18BAC77177CEB2395EF18F";
        sKEY = "00000000000000000000000000000000";
        sCheck = "FC444017478822797D800F790622D77B";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        sPT = "62D0D531FD18BAC77177CEB2395EF18F";
        sKEY = "00000000000000000000000000000000";
        sCheck = "FC444017478822797D800F790622D77B";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        sPT = "FC444017478822797D800F790622D77B";
        sKEY = "00000000000000000000000000000000";
        sCheck = "D584ED203C50582BCBF74B0469417EDC";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        //KEYSIZE=192
        sPT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        sKEY = "000000000000000000000000000000000000000000000000";
        sCheck = "97778747D60E425C2B4202599DB856FB";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        sPT = "97778747D60E425C2B4202599DB856FB";
        sKEY = "000000000000000000000000000000000000000000000000";
        sCheck = "885C6C280610DA436936E3C5AEEB9512";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        //KEYSIZE = 256
        sPT = "62E45B4CF3477F1DD65063729D9ABA8F";
        sKEY = "0000000000000000000000000000000000000000000000000000000000000000";
        sCheck = "0F4B897EA014D21FBC20F1054A42F719";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);

        sPT = "0F4B897EA014D21FBC20F1054A42F719";
        sKEY = "0000000000000000000000000000000000000000000000000000000000000000";
        sCheck = "9A4D42A7F27D42E542286ACF6650CF8A";
        PT = Mars.hexStringToByteArray(sPT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.encrypt(PT,key);
        encrypted = Mars.bytesToHex(out);

        assertEquals(encrypted, sCheck);


    }

    @org.junit.jupiter.api.Test
    void decrypt() {
        //KEYSIZE=128
        String sCT = "B8AB0608C7976E1D8F57B2BA493C7503";
        String sKEY = "00000000000000000000000000000000";
        String sCheck = "77D40822866C0DD51E0594AA81E5F1B5";
        byte[] CT = Mars.hexStringToByteArray(sCT);
        byte[] key = Mars.hexStringToByteArray(sKEY);
        byte[] out;

        out = Mars.decrypt(CT, key);
        String decrypted = Mars.bytesToHex(out);
        assertEquals(decrypted, sCheck);

        sCT = "9213B43D06D0AB7ECCC5CA751C5DBAA8";
        sKEY = "00000000000000000000000000000000";
        sCheck = "53944CA7C3BBBBE32C9BA9D8A8B765D6";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);


        sCT = "ED4AFE77CE3A2F8C00D0A5E4FDF23426";
        sKEY = "00000000000000000000000000000000";
        sCheck = "B8AB0608C7976E1D8F57B2BA493C7503";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);


        sCT = "67D5BD878FF66CDB33A4DD07EB634F91";
        sKEY = "00000000000000000000000000000000";
        sCheck = "29A212AF4220054975D7C2AE9242AFA8";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);

        //KEYSIZE=192
        sCT = "97778747D60E425C2B4202599DB856FB";
        sKEY = "000000000000000000000000000000000000000000000000";
        sCheck = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);


        sCT = "B7028947854FE0C670E1E7416C2803DC";
        sKEY = "000000000000000000000000000000000000000000000000";
        sCheck = "35F8044736D1FF4142460E4E72610700";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);


        sCT = "77F1D30164CD2984C52ACEC02CAE2CD9";
        sKEY = "000000000000000000000000000000000000000000000000";
        sCheck = "D4F8A703F24F7E0AC5807EADADCA8CC9";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);


        //KEYSIZE=256
        sCT = "1D1FEFBD55AA23487CD2DEC4D370302D";
        sKEY = "0000000000000000000000000000000000000000000000000000000000000000";
        sCheck = "980089430C89563A5510DF5196E07040";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);



        sCT = "73A8AAE732EF445F3462353181168B23";
        sKEY = "0000000000000000000000000000000000000000000000000000000000000000";
        sCheck = "1D1FEFBD55AA23487CD2DEC4D370302D";
        CT = Mars.hexStringToByteArray(sCT);
        key = Mars.hexStringToByteArray(sKEY);
        out = Mars.decrypt(CT,key);
        decrypted = Mars.bytesToHex(out);

        assertEquals(decrypted, sCheck);
    }
}