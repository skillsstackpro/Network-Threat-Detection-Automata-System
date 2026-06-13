/* 
 * NETWORK THREAT DETECTION SYSTEM 
 * Stateful FSM Tracking / Turing Machine Logic 
 * (Diagram-Accurate with Practical Nomenclature) 
 */ 
 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
 
/* --- TCP Flag tokens (Sigma) --- */ 
#define FLAG_SYN 0 
#define FLAG_ACK 1 
#define FLAG_RST 2 
#define FLAG_FIN 3 
#define FLAG_URG 4 
#define FLAG_PAY 5 
#define FLAG_SIG 6 
#define FLAG_BLANK 7 
#define TOTAL_FLAGS 8 
 
/* --- TM States (Q) --- */ 
#define STATE_START 0     /* q0: Entry point */ 
#define STATE_SCAN 1      /* q1: SYN Scanning track */ 
#define STATE_COUNT 2     /* q2: Normal flow counting track */ 
#define STATE_ANOMALY 3   /* q3: Deep anomaly check */ 
#define STATE_INSPECT 4   /* q4: Payload inspection track */ 
#define STATE_MATCH 5     /* q5: Signature matching */ 
#define STATE_THREAT 6    /* HALT: Attack confirmed (Block) */ 
#define STATE_CLEAN 7     /* HALT: Traffic safe (Allow) */ 
#define STATE_ESCALATE 8  /* HALT: Unsure (Human/SIEM) */ 
 
/* --- Tape write symbols (Gamma) --- */ 
#define SYM_BLANK 'B' 
#define SYM_SYN 'Y' 
#define SYM_ACK 'A' 
#define SYM_PAY 'P' 
#define SYM_SIG 'G' 
#define SYM_COUNTED 'S'   /* Processed SYN or Signature */ 
#define SYM_MARKED 'X'    /* Confirmed evidence tracker */ 
#define SYM_UNKNOWN 'U'   /* Unrecognized pattern */ 
#define SYM_OK 'O'        /* Clean payload data */ 
#define SYM_THREAT 'T'    /* Confirmed threat output */ 
#define SYM_AMB '?'       /* Ambiguous data */ 
 
/* --- Head movement directions --- */ 
#define MOVE_RIGHT 1 
#define MOVE_LEFT -1 
#define MOVE_STAY 0 
 
/* --- System Limits --- */ 
#define MAX_IPS 10 
#define MAX_FLAGS 20 
#define IP_LENGTH 20 
#define MAX_STEPS 100 
#define SYN_THRESHOLD 5   /* N value for anomaly trigger */ 
 
/* --- Data Structures --- */ 
 
typedef struct { 
    char ip_address[IP_LENGTH]; 
    int flags[MAX_FLAGS]; 
    int flag_count; 
} Packet2D; 
 
typedef struct { 
    char tape[MAX_FLAGS + 5]; 
    int head; 
    int state; 
    int syn_count; 
    int steps; 
} TuringMachine; 
 
/* --- UI / Helper Functions --- */ 
 
void print_line() { 
    printf("--------------------------------------------------\n"); 
} 
 
void print_double_line() { 
    printf("==================================================\n"); 
} 
 
const char* flag_name(int flag) { 
    switch(flag) { 
        case FLAG_SYN: return "SYN "; 
        case FLAG_ACK: return "ACK "; 
        case FLAG_RST: return "RST "; 
        case FLAG_FIN: return "FIN "; 
        case FLAG_URG: return "URG "; 
        case FLAG_PAY: return "PAY "; 
        case FLAG_SIG: return "SIG "; 
        case FLAG_BLANK: return "BLANK"; 
        default: return "?????"; 
    } 
} 
 
const char* state_name(int state) { 
    switch(state) { 
        case STATE_START: return "q0-START "; 
        case STATE_SCAN: return "q1-SCAN "; 
        case STATE_COUNT: return "q2-COUNT "; 
        case STATE_ANOMALY: return "q3-ANOMALY "; 
        case STATE_INSPECT: return "q4-INSPECT "; 
        case STATE_MATCH: return "q5-MATCH "; 
        case STATE_THREAT: return "HALT-THREAT "; 
        case STATE_CLEAN: return "HALT-CLEAN "; 
        case STATE_ESCALATE: return "HALT-ESCALATE "; 
        default: return "UNKNOWN "; 
    } 
} 
 
char flag_to_tape_char(int flag) { 
    switch(flag) { 
        case FLAG_SYN: return SYM_SYN; 
        case FLAG_ACK: return SYM_ACK; 
        case FLAG_RST: return 'R'; 
        case FLAG_FIN: return 'F'; 
        case FLAG_URG: return 'E'; 
        case FLAG_PAY: return SYM_PAY; 
        case FLAG_SIG: return SYM_SIG; 
        default: return SYM_BLANK; 
    } 
} 
 
void print_tape(TuringMachine *tm, int tape_len) { 
    int i; 
    
    // 1. Print Tape Row
    printf(" Tape:  "); 
    for (i = 0; i < tape_len; i++) { 
        if (i == tm->head) 
            printf("[%c] ", tm->tape[i]); // Current head cell in brackets
        else 
            printf(" %c  ", tm->tape[i]); 
    } 
    printf("\n"); 
    
    // 2. Print Index Row
    printf(" Index: "); 
    for (i = 0; i < tape_len; i++) { 
        printf(" %-2d ", i); 
    } 
    printf("\n"); 
    
    // 3. Print Head Pointer Row (Ab yeh line sirf arrow print karegi)
    printf(" Head:  "); 
    for (i = 0; i < tape_len; i++) { 
        if (i == tm->head) 
            printf(" ^  "); 
        else 
            printf("    "); 
    } 
    printf("\n"); // Yahan line ko khatam kar diya taake gap ka masla hi hal ho jaye
    
    // 4. Print Reading Position on the NEXT LINE
    printf(" Head:  (reading position = %d)\n", tm->head); 
}
void print_2d_table(Packet2D table[], int row_count) { 
    int i, j; 
    print_double_line(); 
    printf(" 2D PACKET TABLE (Row = IP, Cols = Flags)\n"); 
    print_double_line(); 
    printf(" %-4s | %-16s | Flags Sent\n", "Row", "IP Address"); 
    print_line(); 
    for (i = 0; i < row_count; i++) { 
        printf(" %-4d | %-16s | ", i, table[i].ip_address); 
        for (j = 0; j < table[i].flag_count; j++) { 
            printf("%s", flag_name(table[i].flags[j])); 
        } 
        printf("\n"); 
    } 
    print_double_line(); 
} 
 
/* --- User Input Functions --- */ 
 
int get_flag_from_user() { 
    int choice; 
    printf(" Choose flag type:\n"); 
    printf(" 1=SYN, 2=ACK, 3=RST, 4=FIN, 5=URG, 6=PAY, 7=SIG, 0=DONE\n"); 
    printf(" Your choice: "); 
    scanf("%d", &choice); 
    
    switch(choice) { 
        case 1: return FLAG_SYN; 
        case 2: return FLAG_ACK; 
        case 3: return FLAG_RST; 
        case 4: return FLAG_FIN; 
        case 5: return FLAG_URG; 
        case 6: return FLAG_PAY; 
        case 7: return FLAG_SIG; 
        case 0: return FLAG_BLANK; 
        default: 
            printf(" Invalid choice. Using SYN.\n"); 
            return FLAG_SYN; 
    } 
} 
 
void get_user_input(Packet2D table[], int *row_count) { 
    int i, j, flag; 
    char more_ips; 
    print_double_line(); 
    printf(" ENTER NETWORK SESSION DATA\n"); 
    print_double_line(); 
    *row_count = 0; 
    
    do { 
        if (*row_count >= MAX_IPS) { 
            printf(" Maximum %d IPs reached.\n", MAX_IPS); 
            break; 
        } 
        i = *row_count; 
        
        /* --- EDITED PORTION START: IP Address Input Fixed --- */
        printf("\n [IP %d] Enter IP address (e.g. 192.168.1.1): ", i); 
        // Direct scanf use kiya jo extra whitespace/enters ko khud handle karta hai
        scanf("%19s", table[i].ip_address); 
        /* --- EDITED PORTION END --- */
        
        printf(" Now enter flags that IP '%s' sent (enter 0 when done):\n", table[i].ip_address); 
        table[i].flag_count = 0; 
        
        for (j = 0; j < MAX_FLAGS - 1; j++) { 
            printf(" Flag %d: ", j + 1); 
            flag = get_flag_from_user(); 
            if (flag == FLAG_BLANK) break; 
            
            table[i].flags[j] = flag; 
            table[i].flag_count++; 
        } 
        table[i].flags[table[i].flag_count] = FLAG_BLANK; 
        
        if (table[i].flag_count == 0) { 
            printf(" No flags entered for this IP. Skipping.\n"); 
        } else { 
            (*row_count)++; 
            printf(" Saved: IP '%s' with %d flags.\n", table[i].ip_address, table[i].flag_count); 
        } 
        
        printf("\n Add another IP address? (y/n) "); 
        scanf(" %c", &more_ips); 
    } while (more_ips == 'y' || more_ips == 'Y'); 
    
    printf("\n Input complete. %d IP(s) entered.\n", *row_count); 
} 
 
/* --- Turing Machine Logic --- */ 
 
void tm_setup(TuringMachine *tm, Packet2D *row) { 
    int i; 
    for (i = 0; i < MAX_FLAGS + 5; i++) 
        tm->tape[i] = SYM_BLANK; 
        
    for (i = 0; i < row->flag_count; i++) 
        tm->tape[i] = flag_to_tape_char(row->flags[i]); 
        
    tm->tape[row->flag_count] = SYM_BLANK; 
    tm->head = 0; 
    tm->state = STATE_START; 
    tm->syn_count = 0; 
    tm->steps = 0; 
} 
 
/* Transition Function: delta(q, sigma) = (q', sigma', D) */ 
int tm_step(TuringMachine *tm, int tape_len) { 
    char current_sym; 
    int new_state; 
    char write_sym; 
    int direction; 
    char reason[250]; 
    
    if (tm->head < 0 || tm->head >= MAX_FLAGS + 4) return 0; 
    
    current_sym = tm->tape[tm->head]; 
    tm->steps++; 
    
    switch (tm->state) { 
        
        /* q0: Start State */ 
        case STATE_START: 
            if (current_sym == SYM_SYN) { 
                new_state = STATE_SCAN; 
                write_sym = SYM_SYN; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "SYN token -> Track connection in q1-scan."); 
            } else if (current_sym == SYM_PAY || current_sym == SYM_SIG) { 
                new_state = STATE_INSPECT; 
                write_sym = SYM_PAY; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Payload token -> Deep inspect in q4-inspect."); 
            } else { 
                new_state = STATE_COUNT; 
                write_sym = SYM_MARKED; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Standard flow token -> Route to q2-count."); 
            } 
            break; 
            
        /* q1: Scan State (Left side of diagram) */ 
        case STATE_SCAN: 
            if (current_sym == SYM_SYN) { 
                tm->syn_count++; 
                if (tm->syn_count >= SYN_THRESHOLD) { 
                    new_state = STATE_ANOMALY; 
                    write_sym = SYM_MARKED; 
                    direction = MOVE_RIGHT; 
                    snprintf(reason, sizeof(reason), "Threshold exceeded (%d SYNs) -> Route to q3-anomaly.", tm->syn_count); 
                } else { 
                    new_state = STATE_SCAN; 
                    write_sym = SYM_COUNTED; 
                    direction = MOVE_RIGHT; 
                    strcpy(reason, "SYN logged -> Continue scanning in q1."); 
                } 
            } else if (current_sym == SYM_ACK) { 
                new_state = STATE_CLEAN; 
                write_sym = SYM_ACK; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Handshake ACK received -> Safe connection. Route to CLEAN."); 
            } else { 
                new_state = STATE_COUNT; 
                write_sym = SYM_MARKED; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Unexpected scan token -> Divert to general q2-count."); 
            } 
            break; 
 
        /* q2: Count State (Center of diagram) */ 
        case STATE_COUNT: 
            if (current_sym == SYM_BLANK) { 
                new_state = STATE_CLEAN; 
                write_sym = SYM_BLANK; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "End of flow (B) -> Traffic is safe. Route to CLEAN."); 
            } else { 
                new_state = STATE_COUNT; 
                write_sym = SYM_PAY; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Normal packet -> Continue tracking in q2-count."); 
            } 
            break; 
            
        /* q3: Anomaly State */ 
        case STATE_ANOMALY: 
            if (current_sym == SYM_SYN || current_sym == SYM_BLANK) { 
                new_state = STATE_THREAT; 
                write_sym = SYM_MARKED; 
                direction = MOVE_LEFT; 
                strcpy(reason, "Flood verified (No ACK) -> THREAT."); 
            } else if (current_sym == 'R' || current_sym == SYM_SIG) { 
                new_state = STATE_THREAT; 
                write_sym = SYM_MARKED; 
                direction = MOVE_LEFT; 
                strcpy(reason, "Secondary attack vector confirmed -> THREAT."); 
            } else { 
                new_state = STATE_ESCALATE; 
                write_sym = SYM_UNKNOWN; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Unknown anomaly behavior -> ESCALATE."); 
            } 
            break; 
            
        /* q4: Inspect State (Right side of diagram) */ 
        case STATE_INSPECT: 
            if (current_sym == SYM_SIG) { 
                new_state = STATE_MATCH; 
                write_sym = SYM_COUNTED; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Signature identified -> Validate in q5-match."); 
            } else { 
                new_state = STATE_CLEAN; 
                write_sym = SYM_OK; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Payload clear (OK) -> Traffic is safe. Route to CLEAN."); 
            } 
            break; 
            
        /* q5: Match State */ 
        case STATE_MATCH: 
            if (current_sym == SYM_BLANK || current_sym == SYM_SIG) { 
                new_state = STATE_THREAT; 
                write_sym = SYM_THREAT; 
                direction = MOVE_LEFT; 
                strcpy(reason, "Signature cross-validated -> THREAT."); 
            } else { 
                new_state = STATE_ESCALATE; 
                write_sym = SYM_AMB; 
                direction = MOVE_RIGHT; 
                strcpy(reason, "Ambiguous post-signature data -> ESCALATE."); 
            } 
            break; 
            
        /* HALTING STATES */ 
        case STATE_THREAT: 
        case STATE_CLEAN: 
        case STATE_ESCALATE: 
            return 0; /* TM Halted */ 
            
        default: 
            return 0; 
    } 
    
    printf("\n"); 
    print_line(); 
    printf(" STEP %d\n", tm->steps); 
    print_line(); 
    printf(" Current State: %s\n", state_name(tm->state)); 
    printf(" Reading Symbol: '%c'\n", current_sym); 
    printf(" Write Symbol: '%c'\n", write_sym); 
    printf(" Head Movement: %s\n", direction == MOVE_RIGHT ? "RIGHT" : 
    direction == MOVE_LEFT ? "LEFT" : "STAY"); 
    printf(" Next State: %s\n", state_name(new_state)); 
    printf(" Action logic: %s\n", reason); 
    if (tm->syn_count > 0) 
        printf(" Current SYN Count: %d\n", tm->syn_count); 
        
    /* Execute state transition */ 
    tm->tape[tm->head] = write_sym; 
    tm->head += direction; 
    tm->state = new_state; 
    
    /* Boundary safety */ 
    if (tm->head < 0) tm->head = 0; 
    if (tm->head >= MAX_FLAGS + 3) tm->head = MAX_FLAGS + 2; 
    
    printf("\n"); 
    print_tape(tm, tape_len); 
    return 1; 
} 
 
int run_tm_for_ip(Packet2D *row) { 
    TuringMachine tm; 
    int i; 
    int tape_len = row->flag_count + 2; 
    
    tm_setup(&tm, row); 
    print_double_line(); 
    printf(" TURING MACHINE ANALYSIS\n"); 
    printf(" IP Address: %s\n", row->ip_address); 
    printf(" Flags : "); 
    for (i = 0; i < row->flag_count; i++) 
        printf("%s", flag_name(row->flags[i])); 
    printf("\n"); 
    print_double_line(); 
    
    printf(" Initial Tape Configuration:\n"); 
    print_tape(&tm, tape_len); 
    printf("\n Starting state: %s\n", state_name(tm.state)); 
    
    for (i = 0; i < MAX_STEPS; i++) { 
        if (tm.state == STATE_THREAT || tm.state == STATE_CLEAN || tm.state == STATE_ESCALATE) { 
            break; 
        } 
        if (!tm_step(&tm, tape_len)) { 
            break; 
        } 
    } 
    
    print_double_line(); 
    printf(" MACHINE HALTED after %d step(s)\n", tm.steps); 
    printf(" Final Tape Configuration:\n"); 
    print_tape(&tm, tape_len); 
    printf(" Final State: %s\n", state_name(tm.state)); 
    print_double_line(); 
    
    return tm.state; 
} 
 
void process_all_ips(Packet2D table[], int row_count) { 
    int i, result; 
    int verdicts[MAX_IPS]; 
    
    printf("\n"); 
    print_double_line(); 
    printf(" PROCESSING ALL IPS THROUGH TURING MACHINE\n"); 
    print_double_line(); 
    printf(" Total IPs to analyse: %d\n\n", row_count); 
    
    for (i = 0; i < row_count; i++) { 
        printf("\n"); 
        print_double_line(); 
        printf(" ANALYSING IP %d of %d: %s\n", i + 1, row_count, table[i].ip_address); 
        print_double_line(); 
        
        result = run_tm_for_ip(&table[i]); 
        verdicts[i] = result; 
        
        printf("\n"); 
        print_double_line(); 
        printf(" VERDICT FOR IP: %s\n", table[i].ip_address); 
        print_double_line(); 
        
        if (result == STATE_THREAT) { 
            printf(" *** THREAT DETECTED ***\n"); 
            printf(" Action: BLOCK this IP immediately & Alert SIEM!\n"); 
        } else if (result == STATE_CLEAN) { 
            printf(" TRAFFIC IS CLEAN \n"); 
            printf(" Action: ALLOW this traffic through.\n"); 
        } else { 
            printf(" CANNOT DECIDE \n"); 
            printf(" Action: Send to human security analyst for review.\n"); 
        } 
        print_double_line(); 
    } 
    
    printf("\n\n"); 
    print_double_line(); 
    printf(" FINAL SUMMARY ALL IPs\n"); 
    print_double_line(); 
    printf(" %-4s | %-16s | %-10s | Action\n", "No.", "IP Address", "Verdict"); 
    print_line(); 
    for (i = 0; i < row_count; i++) { 
        const char *verdict_str; 
        const char *action_str; 
        
        if (verdicts[i] == STATE_THREAT) { 
            verdict_str = "THREAT "; 
            action_str = "BLOCK"; 
        } else if (verdicts[i] == STATE_CLEAN) { 
            verdict_str = "CLEAN "; 
            action_str = "ALLOW"; 
        } else { 
            verdict_str = "ESCALATE "; 
            action_str = "REVIEW"; 
        } 
        printf(" %-4d | %-16s | %-10s | %s\n", i + 1, table[i].ip_address, verdict_str, action_str); 
    } 
    print_double_line(); 
} 
 
/* --- Entry Point --- */ 
int main() { 
    Packet2D table[MAX_IPS]; 
    int row_count = 0; 
    
    print_double_line(); 
    printf(" NETWORK THREAT DETECTION SYSTEM\n"); 
    printf(" Stateful FSM Tracking / Turing Machine Logic\n"); 
    print_double_line(); 
    printf("\n HOW THIS WORKS:\n"); 
    printf(" 1. Provide IP addresses and associated TCP packet flags.\n"); 
    printf(" 2. Data is tracked in a stateful 2D tracking matrix.\n"); 
    printf(" 3. TM transitions evaluate packets sequentially based on flow history.\n"); 
    printf(" 4. Final routing state: THREAT, CLEAN, or ESCALATE.\n\n"); 
    get_user_input(table, &row_count); 
if (row_count == 0) { 
printf("\nNo IPs entered. Exiting.\n"); 
return 0; 
} 
printf("\n Stateful Connection Matrix:\n"); 
print_2d_table(table, row_count); 
process_all_ips(table, row_count); 
printf("\n Analysis Complete.\n"); 
print_double_line(); 
return 0; 
} 