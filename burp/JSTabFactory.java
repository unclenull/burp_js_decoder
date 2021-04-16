package burp;
import java.awt.Component;

public class JSTabFactory implements IMessageEditorTabFactory
{	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new JSTab(editable);
	}
}


class JSTab implements IMessageEditorTab
{
	private ITextEditor txtInput;
	private byte[] originContent;
	private static IExtensionHelpers helpers;

  public JSTab(boolean editable)
	{
		txtInput = BurpExtender.callbacks.createTextEditor();
		txtInput.setEditable(editable);
		JSTab.helpers = helpers;
	}

	@Override
	public String getTabCaption()
	{
		return "JSUnicode";
	}

	@Override
	public Component getUiComponent()
	{
		return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest)
	{
    return BurpExtender.exists_quoted(new String(content));
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest)
	{
    byte[] displayContent;

    originContent = content;

    if(content == null) {
      displayContent = "Nothing to show".getBytes();
    } else {
      try {
        displayContent = BurpExtender.decode_quoted(new String(content)).getBytes();
      } catch (Exception ex) {
        displayContent = ex.getMessage().getBytes();
        ex.printStackTrace(BurpExtender.errorStream);
      }
    }

    txtInput.setText(displayContent);
	}

	@Override
	public byte[] getMessage()
	{
		//change the return value of getMessage() method to the origin content to tell burp don't change the original response
		return originContent;

	}

	@Override
	public boolean isModified()
	{
		//change the return value of isModified() method to false. to let burp don't change the original response) 
		return false;
	}

	@Override
	public byte[] getSelectedData()
	{
		return txtInput.getSelectedText();
	}
}
