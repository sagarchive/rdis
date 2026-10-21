import ghidra.app.script.GhidraScript;

public class EnableParamId extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
    }
}
