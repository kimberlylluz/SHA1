package sha1;

import java.io.*;
import java.nio.*;
import java.util.*;

public class SHA1{
    int j, temp;
    int A, B, C, D, E, F;
    int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
	
	public SHA1(){
		String choice;
		Scanner input = new Scanner(System.in);
        Hash hash = new Hash();
		
		do{
			System.out.println("....................................................................................\n"
				 + "Secure Hash Algorithm 1\nA. String\nB. Set of strings\nC. Exit\n....................................................................................\nChoice: ");
			choice = input.nextLine();
			if(choice.equals("a") || choice.equals("A")){
				System.out.println("Enter string: ");
				String message = input.nextLine();
				//byte array of ASCII values per character in the message
				byte[] dataBuffer = (message).getBytes();
				String digest = hash.digest(dataBuffer);
				System.out.println("....................................................................................\nInput message: " + message);
				System.out.println("Message Hash: " + digest);
			}
			else if(choice.equals("b") || choice.equals("B")){
				System.out.println("Enter set of strings: (dashes in between)");
				String set = input.nextLine();

				String[] setStrings;
				String delimeter = "-";
				setStrings = set.split(delimeter);
				
				System.out.println("....................................................................................\nMessage Hash: ");
				for(int i = 0; i < setStrings.length; i++) {
					byte[] dataBuffer = (setStrings[i]).getBytes();
					String digest = hash.digest(dataBuffer);
					System.out.print(digest);
					if(i != (setStrings.length - 1))
						System.out.print("-");
				}
				System.out.println();
			}
			else if(choice.equals("c") || choice.equals("C")){
				break;
			}
		}while(!(choice.equals("c")) || !(choice.equals("C")));
	}

    public class Hash {

        String digest(byte[] data) {
            byte[] paddedMessage = messagePadding(data);
            int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            int[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

            if (paddedMessage.length % 64 != 0) {
                System.out.println("Invalid padded data length.");
                System.exit(0);
            }

            int numBlocks = paddedMessage.length / 64;
            byte[] W = new byte[64];

            for (int i = 0; i < numBlocks; i++) {
                System.arraycopy(paddedMessage, 64 * i, W, 0, 64);
                processBlock(W, H, K);
            }

            return intArrayToHexStr(H);
        }

        private byte[] messagePadding(byte[] message) {
            int msgLength = message.length;
            int appendLength = 0;
			if (msgLength <= 55) {
                appendLength = 64 - msgLength;
            }
			else {
                appendLength = 128 - (msgLength % 64);
            }

            byte[] append = new byte[appendLength];
            append[0] = (byte) 0x80;
            long lengthInBits = msgLength * 8;
				
            for (int i = 0; i < 8; i++) {
                append[append.length - 1 - i] = (byte) ((lengthInBits >> (8 * i)) 
															& 0x00000000000000FF);
            }

            byte[] paddedMessage = new byte[msgLength + appendLength];
			
			System.arraycopy(message, 0, paddedMessage, 0, msgLength);
            System.arraycopy(append, 0, paddedMessage, msgLength, append.length);

            return paddedMessage;
        }

        private void processBlock(byte[] w, int[] H, int[] K) {
            int[] W = new int[80];
            for (int outer = 0; outer < 16; outer++) {
                int temp = 0;
                for (int inner = 0; inner < 4; inner++) {
                    temp = (w[outer * 4 + inner] & 0x000000FF) << (24 - inner * 8);
                    W[outer] = W[outer] | temp;
                }
            }
			
            for (int j = 16; j < 80; j++){
                W[j] = rotateLeft(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
			}
				
            A = H[0];
            B = H[1];
            C = H[2];
            D = H[3];
            E = H[4];

            for (int j = 0; j < 20; j++) {
                F = (B & C) | ((~B) & D);
                temp = rotateLeft(A, 5) + F + E + K[0] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 20; j < 40; j++) {
                F = B ^ C ^ D;
                temp = rotateLeft(A, 5) + F + E + K[1] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 40; j < 60; j++) {
                F = (B & C) | (B & D) | (C & D);
                temp = rotateLeft(A, 5) + F + E + K[2] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 60; j < 80; j++) {
                F = B ^ C ^ D;
                temp = rotateLeft(A, 5) + F + E + K[3] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            H[0] += A;
            H[1] += B;
            H[2] += C;
            H[3] += D;
            H[4] += E;
        }

        final int rotateLeft(int value, int bits) {
            int q = (value << bits) | (value >>> (32 - bits));
            return q;
        }
    }

    private String intArrayToHexStr(int[] data) {
        String output = "";
        String tempStr = "";
        int tempInt = 0;
        for (int cnt = 0; cnt < data.length; cnt++) {

            tempInt = data[cnt];

            tempStr = Integer.toHexString(tempInt);

            if (tempStr.length() == 1) {
                tempStr = "0000000" + tempStr;
            } else if (tempStr.length() == 2) {
                tempStr = "000000" + tempStr;
            } else if (tempStr.length() == 3) {
                tempStr = "00000" + tempStr;
            } else if (tempStr.length() == 4) {
                tempStr = "0000" + tempStr;
            } else if (tempStr.length() == 5) {
                tempStr = "000" + tempStr;
            } else if (tempStr.length() == 6) {
                tempStr = "00" + tempStr;
            } else if (tempStr.length() == 7) {
                tempStr = "0" + tempStr;
            }
            output = output + tempStr;
        }
        return output;
    }

    static final String toHexString(final ByteBuffer bb) {
        final StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bb.limit(); i += 4) {
            if (i % 4 == 0) {
                sb.append('\n');
            }
            sb.append(toHexString(bb.getInt(i))).append(' ');
        }
        sb.append('\n');
        return sb.toString();
    }

    static final String toHexString(int x) {
        return padStr(Integer.toHexString(x));
    }
    static final String zeros = "00000000";

    static final String padStr(String s) {
        if (s.length() > 8) {
            return s.substring(s.length() - 8);
        }
        return zeros.substring(s.length()) + s;
    }
	public static void main(String[] args) {
		SHA1 sha1 = new SHA1();
    }
}