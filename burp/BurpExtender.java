package burp;
import java.util.regex.Pattern;
import org.apache.commons.text.StringEscapeUtils;
import java.io.PrintStream;

public class BurpExtender implements IBurpExtender
{
  public String ExtenderName = "JS unicode decoder";
  public String github = "https://github.com/unclenull/burp_js_decoder";

  public static IBurpExtenderCallbacks callbacks;
  public static IExtensionHelpers helpers;
  public static Pattern pattern = Pattern.compile("\\\\u(\\p{XDigit}{4})");
  public static Pattern pattern_quoted = Pattern.compile("(\"|')(\\\\u(\\p{XDigit}{4}))+\\1");
  public static PrintStream errorStream;

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
  {
    this.callbacks = callbacks;
    helpers = callbacks.getHelpers();
    errorStream = new PrintStream(callbacks.getStderr());

    callbacks.printOutput(ExtenderName);
    callbacks.printOutput(github);

    callbacks.setExtensionName(ExtenderName);
    callbacks.registerMessageEditorTabFactory(new JSTabFactory());
    callbacks.registerContextMenuFactory(new JSMenuFactory());
  }

  public static String decode(String text) {
    int i=0;
    while (exists(text) && i <= 3) {
      text = StringEscapeUtils.unescapeJava(text);
      i++;
    }

    if (i>0) {
      return text;
    } else {
      return "No JS unicodes to convert.";
    }
  }

  public static String decode_quoted(String text) {
    int i=0;
    while (exists_quoted(text) && i <= 3) {
      text = StringEscapeUtils.unescapeJava(text);
      i++;
    }

    if (i>0) {
      return text;
    } else {
      return "No JS unicodes to convert.";
    }
  }

	public static boolean exists(String str) {
    return pattern.matcher(str.toLowerCase()).find();
	}

	public static boolean exists_quoted(String str) {
    return pattern_quoted.matcher(str.toLowerCase()).find();
	}

	public static void main(String args[]) {
    String[] tests = {"\\u0000\\u0002", "\"\\u0000\\u0002", "\'\\u0000\\u0002", "\"\\u0000\\u0002\"", "'\\u0000\\u0002'"};
    for (int i = 0; i < tests.length; i++) {
      String str = tests[i];
      System.out.print(exists_quoted(str));
      System.out.print(", ");
      System.out.print(exists(str));
      System.out.println();
    }
	}
}
