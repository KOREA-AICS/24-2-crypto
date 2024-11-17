#include <time.h>
#include <stdio.h>
#include <stdint.h>
#define DES_BLOCK_SIZE 64

uint64_t key[3] = { 0x752878397493CB70, 0x752878397493CB70, 0x752878397493CB70 };


uint64_t subkey[3][16] = { 0 };


uint64_t C = 0, D = 0;



int shifts[16] = {
    1,1,2,2,2,2,2,2,
    1,2,2,2,2,2,2,1
};


int pc_1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4 };

int pc_2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32 };


unsigned char IP_table[] = {
58, 50, 42, 34, 26, 18, 10, 2,
60, 52, 44, 36, 28, 20, 12, 4,
62, 54, 46, 38, 30, 22, 14, 6,
64, 56, 48, 40, 32, 24, 16, 8,
57, 49, 41, 33, 25, 17, 9, 1,
59, 51, 43, 35, 27, 19, 11, 3,
61, 53, 45, 37, 29, 21, 13, 5,
63, 55, 47, 39, 31, 23, 15, 7
};

unsigned char E_Box[] = {
32, 1, 2, 3, 4, 5,
4, 5, 6, 7, 8, 9,
8, 9, 10, 11, 12, 13,
12, 13, 14, 15, 16, 17,
16, 17, 18, 19, 20, 21,
20, 21, 22, 23, 24, 25,
24, 25, 26, 27, 28, 29,
28, 29, 30, 31, 32, 1
};

unsigned char S[8][4][16] = {
    // S1
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    // S2
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    // S3
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    // S4
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    // S5
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    // S6
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    // S7
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    // S8
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

unsigned char P_table[] = {
16,7,20,21,29,12,28,17,
1,15,23,26,5,18,31,10,
2,8,24,14,32,27,3,9,
19,13,30,6,22,11,4,25,
};

unsigned char Inverse_IP_table[] = {
40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25
};


void PC1(int key_index) {
    int i;
    uint64_t tmp = 0;
    uint64_t res = 0;

    for (i = 0; i < 56; i++) {
        res <<= 1;
        tmp = (key[key_index] >> (64 - pc_1[i])) & 1;
        res |= tmp;
    }

    C = (res >> 28); // 28비트
    D = (res & 0x0FFFFFFF); // 28비트
}


void circular(int i) {
    C = ((C << shifts[i]) & 0x0FFFFFFF) | (C >> (28 - shifts[i])); // 28비트
    D = ((D << shifts[i]) & 0x0FFFFFFF) | (D >> (28 - shifts[i])); // 28비트
}

void PC2(int i, int key_index) {
    uint64_t tmp = 0;
    uint64_t combined = (C << 28) | D;
    uint64_t res = 0;

    int count;

    for (count = 0; count < 48; count++) {
        res <<= 1;
        tmp = (combined >> (56 - pc_2[count])) & 1;
        res |= tmp;
    }

    uint64_t simC = 0, simD = 0;

    simC = (res >> 24);
    simD = (res & 0x00FFFFFF);
    subkey[key_index][i] = ((simC << 24) | simD) & 0xffffffffffff;

}

void generate_subkey() {

    int i;
    int key_index = 0;

    for (key_index = 0; key_index < 3; key_index++) {

        PC1(key_index);

        for (i = 0; i < 16; i++) {
            circular(i); // circular로 시프트해서 비트 추출해서 뒤에 추가해주고            
            PC2(i, key_index); // PC2 함수로 C D 각각 24비트 리턴
        }
    }


}

void IP(uint64_t* inputP) {
    uint64_t temp = 0;
    int i = 0;

    for (i = 0; i < DES_BLOCK_SIZE; i++) {
        int bit = (*inputP >> (DES_BLOCK_SIZE - IP_table[i])) & 1;
        temp |= ((uint64_t)bit << (DES_BLOCK_SIZE - i - 1));
    }

    *inputP = temp;
}
void InverseIP(uint64_t* inputP) {
    uint64_t temp = 0;
    int i = 0;

    for (i = 0; i < DES_BLOCK_SIZE; i++) {
        int bit = (*inputP >> (DES_BLOCK_SIZE - Inverse_IP_table[i])) & 1;
        temp |= ((uint64_t)bit << (DES_BLOCK_SIZE - i - 1));
    }

    *inputP = temp;
}
uint64_t E(uint32_t inputR) {
    uint64_t outR = 0;
    int i = 0;

    for (i = 0; i < 48; i++) {
        int bit = (inputR >> (32 - E_Box[i])) & 1;
        outR |= ((uint64_t)bit << (48 - i - 1));
    }

    return outR;
}

uint32_t P(uint32_t inputS) {
    uint32_t outputP = 0;
    int i = 0;

    for (i = 0; i < 32; i++) {
        int bit = (inputS >> (32 - P_table[i])) & 1;
        outputP |= ((uint32_t)bit << (32 - i - 1));
    }

    return outputP;
}

uint64_t XOR(uint64_t outR, uint64_t subKey) {
    uint64_t outXOR = outR ^ subKey;
    return outXOR;
}

uint32_t S_Box(uint64_t outXOR) {
    int i = 0;
    int j = 0;
    uint32_t outS = 0;
    uint8_t temp;
    int row;
    int col;


    for (i = 0; i < 8; i++) {
        temp = 0;
        row = 0;
        col = 0;
        for (j = 0; j < 6; j++) {
            uint8_t bit = (outXOR >> (48 - (6 * i + j + 1))) & 1;
            temp |= (bit << (5 - j));
        }
        row = ((temp & 0x20) >> 4) | (temp & 0x01);
        col = (temp & 0x1e) >> 1;
        outS |= S[i][row][col] << (28 - (4 * i));
    }

    return outS;
}

uint32_t Feistel(uint32_t R, uint64_t subKey) {

    uint64_t expandedR = E(R);
    uint64_t xorRes = XOR(expandedR, subKey);
    uint32_t sBoxRes = S_Box(xorRes);
    uint32_t pRes = P(sBoxRes);

    return pRes;
}

void des_encrypt(uint64_t* block, int key_index) {

    int round = 0;

    generate_subkey();

    IP(block);

    uint32_t left = (uint32_t)(*block >> 32);
    uint32_t right = (uint32_t)(*block & 0xffffffff);

    for (round = 0; round < 16; round++) {
        uint64_t feistelRes = Feistel(right, subkey[key_index][round]);
        uint32_t new_right = XOR(left, feistelRes);
        left = right;
        right = new_right;
    }

    uint64_t combined = ((uint64_t)right << 32) | left;

    InverseIP(&combined);

    *block = combined;
}


void des_decrypt(uint64_t* block, int key_index) {

    int round = 0;

    generate_subkey();

    IP(block);

    uint32_t left = (uint32_t)(*block >> 32);
    uint32_t right = (uint32_t)(*block & 0xffffffff);

    for (round = 0; round < 16; round++) {
        uint64_t feistelRes = Feistel(right, subkey[key_index][15 - round]);
        uint32_t new_right = XOR(left, feistelRes);
        left = right;
        right = new_right;
    }

    uint64_t combined = ((uint64_t)right << 32) | left;

    InverseIP(&combined);

    *block = combined;
}

int main() {
    uint64_t plaintext = 0x1122334455667788;
    int i, j;

    clock_t start = clock();

    FILE* file = fopen("output_3des.txt", "a");

    // 파일 열기 실패 여부 확인
    if (file == NULL) {
        printf("파일을 열 수 없습니다.\n");
        return 1; // 오류 코드 반환
    }


    for (i = 0; i < 1000; i++) {

        clock_t start = clock();

        for (j = 0; j < 1000; j++) {
            des_encrypt(&plaintext, 0);
            des_decrypt(&plaintext, 1);
            des_encrypt(&plaintext, 2);//암호화

            des_decrypt(&plaintext, 2);
            des_encrypt(&plaintext, 1);
            des_decrypt(&plaintext, 0);//복호화
        }

        clock_t end = clock();

        fprintf(file, "%lf\n", (double)(end - start) / CLOCKS_PER_SEC);
    }
   
    fclose(file);

}
