package burp;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.commons.text.StringEscapeUtils;
import java.io.PrintStream;

public class BurpExtender implements IBurpExtender
{
  public String ExtenderName = "JS unicode decoder";
  public String github = "https://github.com/unclenull/burp_js_decoder";

  public static IBurpExtenderCallbacks callbacks;
  public static IExtensionHelpers helpers;
  public static Pattern pattern_bare = Pattern.compile("\\\\u(\\p{XDigit}{4})");
  public static Pattern pattern_quoted = Pattern.compile("(\"|')(\\\\u(\\p{XDigit}{4}))+\\1");
  public static PrintStream errorStream;

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
  {
    BurpExtender.callbacks = callbacks;
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
    while (exists(text) != null && i <= 3) {
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
    String new_text = "";
    Matcher matcher = null;
    while ((matcher = exists_quoted(text)) !=null && i <= 3) {
      int beginning = 0;
      do { // replace quoted strings one by one, in case those unquoted are touched.
        int start = matcher.start();
        int end = matcher.end();
        String subtext = text.substring(start, end);
        subtext = StringEscapeUtils.unescapeJava(subtext);

        new_text += text.substring(beginning, start) + subtext;

        beginning = end;
      } while (matcher.find());
      new_text += text.substring(beginning);

      text = new_text;
      i++;
    }

    if (i>0) {
      return new_text;
    } else {
      return "No JS unicodes to convert.";
    }
  }

	public static Matcher exists(String str) {
    return check(str, pattern_bare);
	}

	public static Matcher exists_quoted(String str) {
    return check(str, pattern_quoted);
  }

	public static Matcher check(String str, Pattern pattern) {
    Matcher matcher = pattern.matcher(str.toLowerCase());

    if (matcher.find()) {
      return matcher;
    } else {
      return null;
    }
	}

	public static void main(String args[]) {
    String[] tests = {"\\u0000\\u0002", "\"\\u0000\\u0002", "\'\\u0000\\u0002", "\"\\u0000\\u0002\"", "'\\u0000\\u0002'"};
    for (int i = 0; i < tests.length; i++) {
      String str = tests[i];
      System.out.print(exists_quoted(str) != null);
      System.out.print(", ");
      System.out.print(exists(str) != null);
      System.out.println();
    }
	}
}
