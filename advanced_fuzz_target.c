#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//----------------------------------------------------------------------
// Configuración de guardas para detectar sobrescritura de memoria
//----------------------------------------------------------------------

#define GUARD_SIZE 8
#define GUARD_BYTE 0xAB

//----------------------------------------------------------------------
// Macros para depuración
//----------------------------------------------------------------------

#ifdef DEBUG
  #define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", msg); __builtin_trap(); } while(0)
#else
  #define FAIL(msg) __builtin_trap()
#endif

//----------------------------------------------------------------------
// Asignación y liberación segura de memoria
//----------------------------------------------------------------------

// Reserva memoria con guardas al principio y final.
static void *safe_malloc(size_t size) {
    size_t total = size + 2 * GUARD_SIZE;
    uint8_t *ptr = malloc(total);
    if (!ptr) return NULL;
    memset(ptr, GUARD_BYTE, GUARD_SIZE);                      // Guarda inicial
    memset(ptr + GUARD_SIZE + size, GUARD_BYTE, GUARD_SIZE);    // Guarda final
    return (void *)(ptr + GUARD_SIZE);
}

// Redimensiona la memoria asignada con guardas conservándolas.
static void *safe_realloc(void *p, size_t old_size, size_t new_size) {
    if (!p) return safe_malloc(new_size);
    uint8_t *orig = (uint8_t *)p - GUARD_SIZE;
    size_t total_new = new_size + 2 * GUARD_SIZE;
    uint8_t *new_orig = realloc(orig, total_new);
    if (!new_orig) return NULL;
    memset(new_orig, GUARD_BYTE, GUARD_SIZE);
    memset(new_orig + GUARD_SIZE + new_size, GUARD_BYTE, GUARD_SIZE);
    return (void *)(new_orig + GUARD_SIZE);
}

// Libera la memoria asignada y verifica las guardas.
static void safe_free(void *p, size_t size) {
    if (!p) return;
    uint8_t *ptr = (uint8_t *)p - GUARD_SIZE;
    uint8_t guard[GUARD_SIZE];
    memset(guard, GUARD_BYTE, GUARD_SIZE);
    if (memcmp(ptr, guard, GUARD_SIZE) != 0)
        FAIL("Guard bytes iniciales modificados");
    if (memcmp(ptr + GUARD_SIZE + size, guard, GUARD_SIZE) != 0)
        FAIL("Guard bytes finales modificados");
    free(ptr);
}

//----------------------------------------------------------------------
// Función auxiliar para liberar un arreglo de tokens
//----------------------------------------------------------------------

static void cleanup_tokens(char **tokens) {
    if (!tokens) return;
    for (size_t i = 0; tokens[i] != NULL; i++) {
        size_t len = strlen(tokens[i]) + 1;
        safe_free(tokens[i], len);
    }
    free(tokens);
}

//----------------------------------------------------------------------
// Función auxiliar para comparar token arrays (opcional)
//----------------------------------------------------------------------

static int compare_token_arrays(char **a, char **b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (strcmp(a[i], b[i]) != 0)
            return 0;
        i++;
    }
    return (a[i] == b[i]); // Debe terminar simultáneamente
}

//----------------------------------------------------------------------
// Tokenización avanzada
//----------------------------------------------------------------------
// Esta función procesa la cadena de entrada, manejando tokens
// con o sin comillas y decodificando secuencias de escape en comillas.
char **advanced_tokenize(const char *input, size_t *count) {
    if (!input || !count) return NULL;
    size_t capacity = 16, numTokens = 0;
    char **tokens = malloc(capacity * sizeof(char *));
    if (!tokens) return NULL;

    enum { STATE_DEFAULT, STATE_IN_QUOTE } state = STATE_DEFAULT;
    const char *start = NULL;  // Para tokens sin comillas.
    size_t len = 0;

    // Variables para construir tokens entre comillas.
    char *quote_buffer = NULL;
    size_t quote_len = 0, quote_capacity = 0;

    for (const char *p = input; ; p++) {
        char c = *p;
        switch (state) {
            case STATE_DEFAULT:
                if (c == '\"') {
                    state = STATE_IN_QUOTE;
                    // Inicializamos un buffer para la cadena entre comillas.
                    quote_capacity = strlen(p + 1) + 1;
                    quote_buffer = safe_malloc(quote_capacity);
                    if (!quote_buffer) goto error;
                    quote_len = 0;
                } else if (c == ' ' || c == '\t' || c == '\n' || c == '\0') {
                    if (start) {
                        // Finaliza token sin comillas.
                        char *token = safe_malloc(len + 1);
                        if (!token) goto error;
                        memcpy(token, start, len);
                        token[len] = '\0';
                        if (numTokens >= capacity) {
                            capacity *= 2;
                            char **tmp = realloc(tokens, capacity * sizeof(char *));
                            if (!tmp) { safe_free(token, len + 1); goto error; }
                            tokens = tmp;
                        }
                        tokens[numTokens++] = token;
                        start = NULL;
                        len = 0;
                    }
                    if (c == '\0')
                        goto finish;
                } else {
                    if (!start) {
                        start = p;
                        len = 0;
                    }
                    len++;
                }
                break;

            case STATE_IN_QUOTE:
                if (c == '\\' && *(p+1) != '\0') {
                    // Se omite '\' y se copia el siguiente carácter.
                    p++;
                    if (quote_len + 1 >= quote_capacity) {
                        size_t new_capacity = quote_capacity * 2;
                        char *new_buf = safe_realloc(quote_buffer, quote_capacity, new_capacity);
                        if (!new_buf) { safe_free(quote_buffer, quote_capacity); goto error; }
                        quote_buffer = new_buf;
                        quote_capacity = new_capacity;
                    }
                    quote_buffer[quote_len++] = *p;
                } else if (c == '\"' || c == '\0') {
                    // Fin del token entre comillas.
                    quote_buffer[quote_len] = '\0';
                    char *token = safe_malloc(quote_len + 1);
                    if (!token) { safe_free(quote_buffer, quote_capacity); goto error; }
                    memcpy(token, quote_buffer, quote_len + 1);
                    if (numTokens >= capacity) {
                        capacity *= 2;
                        char **tmp = realloc(tokens, capacity * sizeof(char *));
                        if (!tmp) { safe_free(token, quote_len + 1); safe_free(quote_buffer, quote_capacity); goto error; }
                        tokens = tmp;
                    }
                    tokens[numTokens++] = token;
                    state = STATE_DEFAULT;
                    safe_free(quote_buffer, quote_capacity);
                    quote_buffer = NULL;
                    quote_len = 0;
                    quote_capacity = 0;
                    if (c == '\0')
                        goto finish;
                } else {
                    // Copia el carácter en el token entre comillas.
                    if (quote_len + 1 >= quote_capacity) {
                        size_t new_capacity = quote_capacity * 2;
                        char *new_buf = safe_realloc(quote_buffer, quote_capacity, new_capacity);
                        if (!new_buf) { safe_free(quote_buffer, quote_capacity); goto error; }
                        quote_buffer = new_buf;
                        quote_capacity = new_capacity;
                    }
                    quote_buffer[quote_len++] = c;
                }
                break;
        }
    }
finish:
    tokens = realloc(tokens, (numTokens + 1) * sizeof(char *));
    if (!tokens) goto error;
    tokens[numTokens] = NULL;
    *count = numTokens;
    return tokens;
error:
    cleanup_tokens(tokens);
    if (quote_buffer)
        safe_free(quote_buffer, quote_capacity);
    return NULL;
}

//----------------------------------------------------------------------
// Tokenización básica
//----------------------------------------------------------------------
// Separa la cadena en tokens utilizando espacios, tabulaciones y saltos de línea.
char **basic_tokenize(const char *input, size_t *count) {
    if (!input || !count) return NULL;
    size_t capacity = 16, numTokens = 0;
    char **tokens = malloc(capacity * sizeof(char *));
    if (!tokens) return NULL;
    const char *p = input;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (*p == '\0')
            break;
        const char *start = p;
        size_t len = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            len++;
            p++;
        }
        char *token = safe_malloc(len + 1);
        if (!token)
            goto error;
        memcpy(token, start, len);
        token[len] = '\0';
        if (numTokens >= capacity) {
            capacity *= 2;
            char **tmp = realloc(tokens, capacity * sizeof(char *));
            if (!tmp) { safe_free(token, len + 1); goto error; }
            tokens = tmp;
        }
        tokens[numTokens++] = token;
    }
    tokens = realloc(tokens, (numTokens + 1) * sizeof(char *));
    if (!tokens) goto error;
    tokens[numTokens] = NULL;
    *count = numTokens;
    return tokens;
error:
    cleanup_tokens(tokens);
    return NULL;
}

//----------------------------------------------------------------------
// Cálculo de hash usando el algoritmo djb2
//----------------------------------------------------------------------

uint32_t compute_hash(char **tokens) {
    uint32_t hash = 5381;
    for (size_t i = 0; tokens[i] != NULL; i++) {
        const unsigned char *p = (const unsigned char *)tokens[i];
        while (*p) {
            hash = ((hash << 5) + hash) + *p; // hash * 33 + c
            p++;
        }
        // Se añade un separador entre tokens
        hash = ((hash << 5) + hash) + ' ';
    }
    return hash;
}

//----------------------------------------------------------------------
// Fuzz Target para OSS-Fuzz (libFuzzer)
//----------------------------------------------------------------------
// Se realizan ambas tokenizaciones y se comparan sus resultados. Si se detecta
// una discrepancia significativa se fuerza un crash, lo cual es intencional para
// facilitar la detección de vulnerabilidades.
//----------------------------------------------------------------------

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4)
        return 0; // No procesar entradas muy cortas

    // Copia la entrada y la hace nula-terminada.
    char *input = safe_malloc(Size + 1);
    if (!input)
        return 0;
    memcpy(input, Data, Size);
    input[Size] = '\0';

    size_t adv_count = 0, basic_count = 0;
    char **adv_tokens = advanced_tokenize(input, &adv_count);
    char **basic_tokens = basic_tokenize(input, &basic_count);

    if (!adv_tokens || !basic_tokens) {
        safe_free(input, Size + 1);
        if (adv_tokens)
            cleanup_tokens(adv_tokens);
        if (basic_tokens)
            cleanup_tokens(basic_tokens);
        return 0;
    }

    // Validación diferencial:
    // 1. Si la diferencia en cantidad de tokens es mayor a 1, se considera inconsistente.
    size_t diff = (adv_count > basic_count) ? (adv_count - basic_count) : (basic_count - adv_count);
    if (diff > 1)
        goto crash;

    // 2. Se comparan los hashes; si difieren demasiado (más del 10% del valor máximo), se dispara fallo.
    uint32_t hash_adv = compute_hash(adv_tokens);
    uint32_t hash_basic = compute_hash(basic_tokens);
    uint32_t max_hash = (hash_adv > hash_basic) ? hash_adv : hash_basic;
    uint32_t min_hash = (hash_adv > hash_basic) ? hash_basic : hash_adv;
    if (max_hash - min_hash > (max_hash / 10))
        goto crash;

    // 3. Prevención de casos extremos.
    if (adv_count > 1000 || basic_count > 1000)
        goto crash;

    // (Opcional) Comparación token a token (descomentar para pruebas de debug)
    // if (!compare_token_arrays(adv_tokens, basic_tokens))
    //     goto crash;

    // Limpieza y salida normal.
    cleanup_tokens(adv_tokens);
    cleanup_tokens(basic_tokens);
    safe_free(input, Size + 1);
    return 0;

crash:
    cleanup_tokens(adv_tokens);
    cleanup_tokens(basic_tokens);
    safe_free(input, Size + 1);
    FAIL("Diferencia significativa en tokenización detectada");
}
