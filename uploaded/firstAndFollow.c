#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX 20

// Data structures
char productions[MAX][MAX];
char nonterminals[MAX];
char terminals[MAX];
char firstSets[MAX][MAX];
char followSets[MAX][MAX];

int prodCount = 0;
int ntCount = 0;
int tCount = 0;

// Utility to check if symbol is a nonterminal
int isNonTerminal(char c) {
    return (c >= 'A' && c <= 'Z');
}

// Add character to a set if not already there
void addToSet(char set[], char c) {
    int i;
    for (i = 0; set[i]; i++)
        if (set[i] == c) return;
    set[i] = c;
    set[i+1] = '\0';
}

// Compute FIRST(X)
void findFirst(char *result, char X) {
    int i, j;
    if (!isNonTerminal(X)) { // X is terminal
        addToSet(result, X);
        return;
    }

    // For each production with head X
    for (i = 0; i < prodCount; i++) {
        if (productions[i][0] == X) {
            // Look at RHS
            for (j = 3; productions[i][j]; j++) {
                char Y = productions[i][j];
                if (Y == '~') {
                    addToSet(result, '~'); // epsilon
                    break;
                } else if (!isNonTerminal(Y)) {
                    addToSet(result, Y);
                    break;
                } else {
                    char temp[MAX] = "";
                    findFirst(temp, Y);
                    int k;
                    int hasEps = 0;
                    for (k = 0; temp[k]; k++) {
                        if (temp[k] == '~') hasEps = 1;
                        else addToSet(result, temp[k]);
                    }
                    if (!hasEps) break; // stop if epsilon not in FIRST(Y)
                    if (productions[i][j+1] == '\0') // all can derive epsilon
                        addToSet(result, '~');
                }
            }
        }
    }
}

// Compute FOLLOW(A)
void findFollow(char *result, char A) {
    int i, j, k;

    if (productions[0][0] == A) // start symbol
        addToSet(result, '$');

    for (i = 0; i < prodCount; i++) {
        for (j = 3; productions[i][j]; j++) {
            if (productions[i][j] == A) {
                // case: A is not last symbol
                if (productions[i][j+1] != '\0') {
                    char beta = productions[i][j+1];
                    if (!isNonTerminal(beta)) {
                        addToSet(result, beta);
                    } else {
                        char temp[MAX] = "";
                        findFirst(temp, beta);
                        int hasEps = 0;
                        for (k = 0; temp[k]; k++) {
                            if (temp[k] == '~') hasEps = 1;
                            else addToSet(result, temp[k]);
                        }
                        if (hasEps) {
                            char temp2[MAX] = "";
                            findFollow(temp2, productions[i][0]);
                            for (k = 0; temp2[k]; k++)
                                addToSet(result, temp2[k]);
                        }
                    }
                } else { // A is at end
                    if (productions[i][0] != A) {
                        char temp[MAX] = "";
                        findFollow(temp, productions[i][0]);
                        for (k = 0; temp[k]; k++)
                            addToSet(result, temp[k]);
                    }
                }
            }
        }
    }
}

int main() {
    int i, j;
    char ch;

    printf("Enter number of productions: ");
    scanf("%d", &prodCount);

    printf("Enter productions (E->smth):\n");
    for (i = 0; i < prodCount; i++) {
        scanf("%s", productions[i]);
    }

    // Collect nonterminals
    for (i = 0; i < prodCount; i++) {
        char nt = productions[i][0];
        int found = 0;
        for (j = 0; j < ntCount; j++)
            if (nonterminals[j] == nt) found = 1;
        if (!found) nonterminals[ntCount++] = nt;
    }

    // Compute FIRST sets
    for (i = 0; i < ntCount; i++) {
        char result[MAX] = "";
        findFirst(result, nonterminals[i]);
        strcpy(firstSets[i], result);
    }

    // Compute FOLLOW sets
    for (i = 0; i < ntCount; i++) {
        char result[MAX] = "";
        findFollow(result, nonterminals[i]);
        strcpy(followSets[i], result);
    }

    printf("\nFIRST sets --\n\n");
    for (i = 0; i < ntCount; i++) {
        printf("FIRST(%c) = { ", nonterminals[i]);
        for (j = 0; firstSets[i][j]; j++)
            printf("%c%s", firstSets[i][j], (firstSets[i][j+1] ? ", " : " "));
        printf("}\n");
    }

    printf("\nFOLLOW sets --\n\n");
    for (i = 0; i < ntCount; i++) {
        printf("FOLLOW(%c) = { ", nonterminals[i]);
        for (j = 0; followSets[i][j]; j++)
            printf("%c%s", followSets[i][j], (followSets[i][j+1] ? ", " : " "));
        printf("}\n");
    }

    return 0;
}
