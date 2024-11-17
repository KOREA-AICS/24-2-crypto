#include <time.h>
#include <stdio.h>
#include <stdint.h>

const unsigned char sbox[16][16] = {
   { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
   { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
   { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
   { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x7},
   { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
   { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
   { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
   { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
   { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
   { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
   { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
   { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
   { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
   { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9},
   { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
   { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};
const unsigned char inv_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};
const unsigned char mixColumnMatrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
const unsigned char InvmixColumnMatrix[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};
const unsigned char Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
}; //0x8d는 사용안함. 인덱스 1~10 사용

//uint8_t plaintext[16] = { 0 }; // 128bit = 16byte

//uint8_t plaintext[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
//uint8_t key[16] = { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 };

//uint8_t plaintext[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
//uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

uint8_t plaintext[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };


uint8_t state[4][4] = { 0 }; // 128bit = 16byte
uint8_t tmp_state[4][4] = { 0 }; // 128bit = 16byte
uint8_t encrypted[16] = { 0 }; // 128bit =16byte
uint8_t decrypted[16] = { 0 }; // 128bit = 16byte
//uint8_t key[16] = { 0 };  // 128/8=16byte
uint32_t w[44] = { 0 }; // 176byte 4 * 44
uint32_t roundKey[11][4] = { 0 }; // 176byte 44 * 4 * 1

int round_index = 0;

uint8_t MUL2(uint8_t a) {
    uint8_t tmp = 0;
    tmp = a << 1;

    if ((a >> 7) == 1) {
        tmp ^= 0x1b;
    }

    return tmp;
}
uint8_t MUL(uint8_t a, uint8_t b) {
    uint8_t tmp = 0;


    for (int i = 0; i < 8; i++) {
        if ((a >> i & 0x01) == 1) {
            tmp ^= b;
        }
        b = MUL2(b);
    }
    return tmp;
}
uint8_t inv(uint8_t a) {
    int i;
    uint8_t tmp = a;

    for (i = 6; i >= 1; i--) {
        tmp = MUL(MUL(tmp, tmp), a);
    }
    tmp = MUL(tmp, tmp);

    return tmp;
}


//keygen start

uint32_t rotWord(uint32_t t) {
    t = (t << 8) | (t >> 24);
    return t;
}
uint32_t subWord(uint32_t t) {
    int i;
    int row, col;
    uint8_t temp = 0;
    uint32_t subWordRes = 0;

    for (i = 0; i < 4; i++) {
        temp = (t >> (24 - i * 8)) & 0xff;
        row = (temp >> 4);
        col = temp & 0xf;
        subWordRes |= sbox[row][col] << (24 - i * 8);
    }

    return subWordRes;
}
void keyGeneration() {
    uint32_t t = 0;
    int i = 0, j = 0;

    for (int i = 0; i < 4; i++) {
        w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    for (i = 0; i < 10; i++) {
        t = w[4 * i + 3];
        t = rotWord(t);
        t = subWord(t);
        t = t ^ (Rcon[i + 1] << 24);

        w[4 * (i + 1)] = w[4 * i] ^ t;
        w[4 * (i + 1) + 1] = w[4 * i + 1] ^ w[4 * (i + 1)];
        w[4 * (i + 1) + 2] = w[4 * i + 2] ^ w[4 * (i + 1) + 1];
        w[4 * (i + 1) + 3] = w[4 * i + 3] ^ w[4 * (i + 1) + 2];
    }

    for (i = 0; i < 4; i++) {
        roundKey[0][i] = w[i];
    }
    for (i = 1; i < 11; i++) {
        for (j = 0; j < 4; j++) {
            roundKey[i][j] = w[4 * i + j];
        }
    }
}

//keygen end



void subBytes() {
    int i = 0, j = 0;

    uint8_t tmp_x = 0;
    uint8_t tmp_y = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_x = tmp_state[i][j] >> 4;
            tmp_y = tmp_state[i][j] & 0x0f;

            state[i][j] = sbox[tmp_x][tmp_y];
        }
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}
void shiftRows() {
    uint8_t tmp = 0;
    int i = 0, j = 0;

    tmp = state[1][0];
    state[1][0] = state[1][1];  state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2]; state[2][2] = tmp; tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;

    tmp = state[3][3];
    state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = tmp;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}
void mixColumns() {
    int i = 0, j = 0;
    for (i = 0; i < 4; i++) {
        state[0][i] = MUL(mixColumnMatrix[0][0], tmp_state[0][i]) ^ MUL(mixColumnMatrix[0][1], tmp_state[1][i]) ^ MUL(mixColumnMatrix[0][2], tmp_state[2][i]) ^ MUL(mixColumnMatrix[0][3], tmp_state[3][i]);
        state[1][i] = MUL(mixColumnMatrix[1][0], tmp_state[0][i]) ^ MUL(mixColumnMatrix[1][1], tmp_state[1][i]) ^ MUL(mixColumnMatrix[1][2], tmp_state[2][i]) ^ MUL(mixColumnMatrix[1][3], tmp_state[3][i]);
        state[2][i] = MUL(mixColumnMatrix[2][0], tmp_state[0][i]) ^ MUL(mixColumnMatrix[2][1], tmp_state[1][i]) ^ MUL(mixColumnMatrix[2][2], tmp_state[2][i]) ^ MUL(mixColumnMatrix[2][3], tmp_state[3][i]);
        state[3][i] = MUL(mixColumnMatrix[3][0], tmp_state[0][i]) ^ MUL(mixColumnMatrix[3][1], tmp_state[1][i]) ^ MUL(mixColumnMatrix[3][2], tmp_state[2][i]) ^ MUL(mixColumnMatrix[3][3], tmp_state[3][i]);
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }

}
void AddRoundKey() {
    int i = 0, j = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= ((roundKey[round_index][j] >> (24 - 8 * i)) & 0xff);
        }
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}

void InvsubBytes() {
    int i = 0, j = 0;

    uint8_t tmp_x = 0;
    uint8_t tmp_y = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_x = tmp_state[i][j] >> 4;
            tmp_y = tmp_state[i][j] & 0x0f;

            state[i][j] = inv_sbox[tmp_x][tmp_y];
        }
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}
void InvshiftRows() {
    uint8_t tmp = 0;
    int i = 0, j = 0;

    tmp = state[1][3];
    state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2]; state[2][2] = tmp; tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;

    tmp = state[3][0];
    state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = tmp;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}
void InvmixColumns() {
    int i = 0, j = 0;
    for (i = 0; i < 4; i++) {
        state[0][i] = MUL(InvmixColumnMatrix[0][0], tmp_state[0][i]) ^ MUL(InvmixColumnMatrix[0][1], tmp_state[1][i]) ^ MUL(InvmixColumnMatrix[0][2], tmp_state[2][i]) ^ MUL(InvmixColumnMatrix[0][3], tmp_state[3][i]);
        state[1][i] = MUL(InvmixColumnMatrix[1][0], tmp_state[0][i]) ^ MUL(InvmixColumnMatrix[1][1], tmp_state[1][i]) ^ MUL(InvmixColumnMatrix[1][2], tmp_state[2][i]) ^ MUL(InvmixColumnMatrix[1][3], tmp_state[3][i]);
        state[2][i] = MUL(InvmixColumnMatrix[2][0], tmp_state[0][i]) ^ MUL(InvmixColumnMatrix[2][1], tmp_state[1][i]) ^ MUL(InvmixColumnMatrix[2][2], tmp_state[2][i]) ^ MUL(InvmixColumnMatrix[2][3], tmp_state[3][i]);
        state[3][i] = MUL(InvmixColumnMatrix[3][0], tmp_state[0][i]) ^ MUL(InvmixColumnMatrix[3][1], tmp_state[1][i]) ^ MUL(InvmixColumnMatrix[3][2], tmp_state[2][i]) ^ MUL(InvmixColumnMatrix[3][3], tmp_state[3][i]);
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}
void InvAddRoundKey() {
    int i = 0, j = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= ((roundKey[round_index][j] >> (24 - 8 * i)) & 0xff);
        }
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            tmp_state[i][j] = state[i][j];
        }
    }
}


void encrypt() {
    int i = 0;
    int j = 0;
    round_index = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            tmp_state[j][i] = state[j][i] = plaintext[4 * i + j];
    } // state 값 생성

    AddRoundKey(); //0라운드
    round_index++;

    for (i = 0; i < 9; i++) {
        subBytes();
        shiftRows();
        mixColumns();
        AddRoundKey();
        round_index++;
    }
    subBytes();
    shiftRows();
    AddRoundKey();

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            encrypted[4 * i + j] = state[j][i];
    } // encrypted 값 생성

}

void decrypt() {
    int i = 0;
    int j = 0;
    round_index = 10;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            tmp_state[j][i] = state[j][i] = encrypted[4 * i + j];
    } // state 값 생성

    InvAddRoundKey(); //10라운드
    round_index--;

    for (i = 0; i < 9; i++) {
        InvshiftRows();
        InvsubBytes();
        InvAddRoundKey();
        InvmixColumns();
        round_index--;
    }
    InvshiftRows();
    InvsubBytes();
    InvAddRoundKey();

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++)
            decrypted[4 * i + j] = state[j][i];
    } // decrypted 값 생성

}


int main(void) {
    int i, j;
    keyGeneration();


    FILE* file = fopen("output_aes.txt", "a");

    // 파일 열기 실패 여부 확인
    if (file == NULL) {
        printf("파일을 열 수 없습니다.\n");
        return 1; // 오류 코드 반환
    }

    for (i = 0; i < 1000; i++) {

        clock_t start = clock();

        for (j = 0; j < 1000; j++) {
            encrypt();
            decrypt();
        }

        clock_t end = clock();       

        // 파일에 데이터 출력
        fprintf(file, "%lf\n", (double)(end - start) / CLOCKS_PER_SEC);

    }

    // 파일 닫기
    fclose(file);

  
    return 0;


}
