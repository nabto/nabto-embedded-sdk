
#include <modules/mbedtls/nm_mbedtls_util.h>
#include <apps/common/string_file.h>
#include <platform/np_util.h>

#include <gopt/gopt.h>
#include <stdio.h>

#ifdef WIN32
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif


enum {
    OPTION_HELP = 1,
    OPTION_OUTPUT,
    OPTION_OUTPUT_FORMAT,
    OPTION_INPUT,
    OPTION_INPUT_FORMAT,
    OPTION_STRING_INPUT
};


struct args {
    bool showHelp;
    const char* output;
    const char* outputFormat;
    const char* input;
    const char* inputFormat;
    const char* stringInput;
};

static bool parse_args(int argc, char** argv, struct args* args)
{
    const char x1s[]  = "h";      const char* x1l[]  = { "help", 0 };
    const char x2s[]  = "o";      const char* x2l[]  = { "output", 0 };
    const char x3s[]  = "";       const char* x3l[]  = { "output-format", 0 };
    const char x4s[]  = "i";      const char* x4l[]  = { "input", 0 };
    const char x5s[]  = "";       const char* x5l[]  = { "input-format", 0 };
    const char x6s[]  = "s";      const char* x6l[]  = { "string-input", 0 };

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { OPTION_HELP, GOPT_NOARG, x1s, x1l },
        { OPTION_OUTPUT, GOPT_ARG, x2s, x2l },
        { OPTION_OUTPUT_FORMAT, GOPT_ARG, x3s, x3l },
        { OPTION_INPUT, GOPT_ARG, x4s, x4l },
        { OPTION_INPUT_FORMAT, GOPT_ARG, x5s, x5l },
        { OPTION_STRING_INPUT, GOPT_ARG, x6s, x6l },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, (const char**)argv, opts);

    if (gopt(options, OPTION_HELP)) {
        args->showHelp = true;
    }

    if (gopt_arg(options, OPTION_OUTPUT, &args->output)) {
    }

    if (!gopt_arg(options, OPTION_OUTPUT_FORMAT, &args->outputFormat)) {
        args->outputFormat = "pem";
    }

    if (gopt_arg(options, OPTION_INPUT, &args->input)) {
    }

    if (gopt_arg(options, OPTION_STRING_INPUT, &args->stringInput)) {
    }

    if (!gopt_arg(options, OPTION_INPUT_FORMAT, &args->inputFormat)) {
        if(args->input == NULL) {
            args->inputFormat = "generate";
        } else {
            args->inputFormat = "raw";
        }
    }
    gopt_free(options);
    return true;
}

void args_init(struct args* args)
{
    memset(args, 0, sizeof(struct args));
}

void args_deinit(struct args* args)
{
}

static void print_help()
{
    printf("Key tool converts a Private key to different formats." NEWLINE);
    //printf("Private key can be provided as ");
    printf(" -h, --help           Print help" NEWLINE);
    printf(" -o, --output         File to write output to. If not specified output is written to stdout" NEWLINE);
    printf("     --output-format  Output format (default: 'pem'). Valid options: 'pem', 'raw', 'fingerprint', 'cert'" NEWLINE);
    printf(" -i, --input          File to read private key from. Not required when generating new key" NEWLINE);
    printf(" -s, --string-input   Provide input directly from command line.");
    printf(
        "     --input-format   Format of the input file (default: if --input "
        "not specified: 'generate'. 'raw' otherwise). Valid options: generate, "
        "pem, raw" NEWLINE);
}

int main(int argc, char** argv)
{
    struct args args;
    args_init(&args);
    if (!parse_args(argc, argv, &args)) {
        printf("Could not parse arguments.");
        print_help();
        args_deinit(&args);
        return 1;
    }

    if (args.showHelp) {
        print_help();
        args_deinit(&args);
        return 1;
    }

    np_error_code ec;
    // Get private key in pem format from somewhere
    char* inputKey;
    if (strcmp(args.inputFormat, "generate") == 0) {
        printf("Generating new key" NEWLINE);
        ec = nm_mbedtls_util_create_private_key(&inputKey);
        if (ec != NABTO_EC_OK) {
            printf("Failed to create key with: %s" NEWLINE, np_error_code_to_string(ec));
            return 1;
        }

    } else if(args.input == NULL && args.stringInput == NULL) {
        printf("Input format '%s' requires input from file or from command line to be provided" NEWLINE, args.inputFormat);
        print_help();
        return 1;
    } else {
        char* inputStr;
        if (args.input != NULL) {
            printf("Parsing input file '%s' with format '%s'" NEWLINE, args.input,
                args.inputFormat);
            if (!string_file_exists(args.input)
            || !string_file_load(args.input, &inputStr)) {
                printf("Failed to load input file %s" NEWLINE, args.input);
                return 1;
            }
        } else if (args.stringInput != NULL) {
            inputStr = strdup(args.stringInput);
        }

        if (strcmp(args.inputFormat, "raw") == 0) {
            // Parse raw private key from loaded file
            if (strlen(inputStr) == 65 && inputStr[64] == '\n') {
                // some editors insist on trailing newlines in files, so we ignore it
                inputStr[64] = 0;
            }

            if (strlen(inputStr) != 64) {
                printf("Invalid input key length: %ld" NEWLINE,
                        strlen(inputStr));
                return 1;
            }
            uint8_t rawKey[32];
            if (!np_hex_to_data(inputStr, rawKey, 32)) {
                printf("FAILED could not convert hex to data" NEWLINE);
                return 1;
            }

            ec = nm_mbedtls_util_pem_from_secp256r1(rawKey, 32, &inputKey);
            if (ec != NABTO_EC_OK) {
                printf("Failed to convert raw key to pem with: %s" NEWLINE, np_error_code_to_string(ec));
                return 1;
            }
        } else if (strcmp(args.inputFormat, "pem") == 0) {
            // File input already pem format, use as is
            inputKey = inputStr;
        } else {
            printf("Invalid input format '%s'" NEWLINE, args.inputFormat);
            print_help();
            return 1;
        }
    }

    // Generate output string based on specified format
    char outputString[1024];
    memset(outputString, 0, 1024);

    if (strcmp(args.outputFormat, "raw") == 0) {
        // Generate raw private key
        uint8_t rawOut[33];
        ec = nm_mbedtls_util_secp256r1_from_pem(inputKey, strlen(inputKey),
                                                rawOut, 32);
        if (ec != NABTO_EC_OK) {
            printf("Failed to convert to raw key with: %s" NEWLINE, np_error_code_to_string(ec));
            return 1;
        }
        np_data_to_hex(rawOut, 32, outputString);
    } else if (strcmp(args.outputFormat, "pem") == 0) {
        // Input is already PEM just copy
        memcpy(outputString, inputKey, strlen(inputKey));
    } else if (strcmp(args.outputFormat, "fingerprint") == 0) {
        // Get fingerprint from private key
        uint8_t fp[32];
        ec =
            nm_mbedtls_get_fingerprint_from_private_key(inputKey, fp);
        if (ec != NABTO_EC_OK) {
            printf("Failed get fingerprint from private key with: %s" NEWLINE, np_error_code_to_string(ec));
            return 1;
        }
        np_data_to_hex(fp, 32, outputString);
    } else if (strcmp(args.outputFormat, "cert") == 0) {
        // Get certificate from private key
        char* cert;
        ec =
            nm_mbedtls_create_crt_from_private_key(inputKey, &cert);
        if (ec != NABTO_EC_OK) {
            printf("Failed create cert from private key with: %s" NEWLINE, np_error_code_to_string(ec));
            return 1;
        }
        memcpy(outputString, cert, strlen(cert));
    } else {
        printf("Invalid output format '%s'" NEWLINE, args.outputFormat);
        print_help();
        return 1;
    }

    // Present the output string as specified
    if (args.output != NULL) {
        // output file provided. Write to file
        printf(
            "Private key from input format '%s' successfully converted to "
            "format '%s'" NEWLINE,
            args.inputFormat, args.outputFormat);
        if (!string_file_save(args.output, outputString)) {
            printf("Failed to save output to file!" NEWLINE);
            return 1;
        } else {
            printf("Output successfully written to file %s" NEWLINE,
                   args.output);
            return 0;
        }

    } else {
        // no output file provided. Write to stdout
        printf(
            "Private key from input format '%s' successfully converted to "
            "format '%s'" NEWLINE,
            args.inputFormat, args.outputFormat);
        printf("Resulting output:" NEWLINE);
        printf("%s" NEWLINE, outputString);
        return 0;
    }
}
