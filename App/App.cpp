#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "[!] Fail to initialize enclave" << std::endl;
        return 1;
    }
    sgx_status_t status;
    FILE *input_file = NULL;
    if (argc > 1) {
        input_file = fopen(argv[1], "rb");
    }
    int input_file_size;
    fseek(input_file, 0, SEEK_END);
    input_file_size = ftell(input_file);
    rewind(input_file);
    printf ("\n[+] Input filesize is %d\n", input_file_size);

    char ptr[input_file_size];
    for (int i=0; i<sizeof(ptr); i++)
	{
		ptr[i] = '0';
	}
    fgets(ptr, input_file_size, input_file);
    //printf("String read: %s\n", ptr);
    std::cout << "[+] String read is: \n\n" << ptr << "\n" << std::endl;
    fclose(input_file);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    unsigned char* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (unsigned char*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "[!] Sealing unsuccesful", ecall_status)) {
        return 1;
    }
    else
        printf("[+] Data sealed\n");

    char unsealed[input_file_size];
    for (int i=0; i<sizeof(unsealed); i++)
	{
		unsealed[i] = '0';
	}
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (unsigned char*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "[!] Unsealing unsuccesful", ecall_status)) {
        return 1;
    }

	if (strcmp(ptr, unsealed) == 0) {
		std::cout << "[+] Seal round trip success! Retrieved string is: \n\n" << unsealed << "\n" << std::endl;
	}
	else
	{
		printf("[!] Unsealed Data doesn't match\n");
		std::cout << "[!] Received back " << unsealed << std::endl;
		return 1;
	}

    return 0;
}
