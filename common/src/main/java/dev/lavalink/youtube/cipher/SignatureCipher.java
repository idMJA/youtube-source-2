package dev.lavalink.youtube.cipher;

import org.jetbrains.annotations.NotNull;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

/**
 * Describes one signature cipher
 */
public class SignatureCipher {
  public final String scriptTimestamp;
  public final String rawScript;

  public SignatureCipher(
      @NotNull String timestamp,
      @NotNull String rawScript) {

    this.scriptTimestamp = timestamp;
    this.rawScript = rawScript;

  }


  /**
   * @param text         Text to transform
   * @param funcName Function name to invoke
   * @param scriptEngine JavaScript engine to execute function
   * @return The result of the n parameter transformation
   */
  public String transform(@NotNull String text,@NotNull String funcName ,  @NotNull ScriptEngine scriptEngine)
      throws ScriptException, NoSuchMethodException {
    String transformed;
    // String patchedScript = rawScript.replaceAll("\\bconst\\b", "var");
    scriptEngine.eval(rawScript);
    transformed = (String) ((Invocable) scriptEngine).invokeFunction(funcName, text);

    return transformed;
  }
  
}