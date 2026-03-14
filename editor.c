#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

static char current_color[64] = "black";

EMSCRIPTEN_KEEPALIVE
char* parse_text(const char* input) {
    static char output[8192]; 
    memset(output, 0, sizeof(output));

    const char* text_start = input; 

   
    if (strncmp(input, "//", 2) == 0) {
        const char* cmd = "//font -c "; 
        
        if (strncmp(input, cmd, strlen(cmd)) == 0) {
            const char* color_start = input + strlen(cmd);
            
         
            const char* color_end = strchr(color_start, '\n');
            
            if (color_end != NULL) {
                
                size_t color_len = color_end - color_start;
                
               
                if (color_len > 0 && color_len < sizeof(current_color) - 1) {
                    strncpy(current_color, color_start, color_len);
                    current_color[color_len] = '\0';
                }
                
               
                text_start = color_end + 1;
            } 
        }
    }

    
    snprintf(output, sizeof(output), "%s|%s", current_color, text_start);
    
    return output;
}