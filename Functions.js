Module.onRuntimeInitialized = function() {
    const parseTextC = Module.cwrap('parse_text', 'string', ['string']);
    const editor = document.getElementById('editor');

    editor.addEventListener('input', function() {
        
        let cursorStart = editor.selectionStart;
        let oldLength = editor.value.length;

       
        const rawOutputFromC = parseTextC(editor.value);
        const separatorIndex = rawOutputFromC.indexOf('|');
        
        if (separatorIndex !== -1) {
            const colorCommand = rawOutputFromC.substring(0, separatorIndex);
            const actualText = rawOutputFromC.substring(separatorIndex + 1);
            
         
            editor.style.color = colorCommand;
            
            
            if (editor.value !== actualText) {
                editor.value = actualText;
                
               
                let lengthDiff = oldLength - actualText.length;
                editor.setSelectionRange(cursorStart - lengthDiff, cursorStart - lengthDiff);
            }
        }
    });
};