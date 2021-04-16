package burp;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JMenuItem;

public class JSMenuFactory implements IContextMenuFactory {
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    int[] bounds = invocation.getSelectionBounds();
    if (bounds == null) {
      BurpExtender.callbacks.printOutput("No string selected.");
      return null;
    }
    int start = bounds[0];
    int end = bounds[1];
    if (start == end) {
      BurpExtender.callbacks.printOutput("No string selected.");
      return null;
    }

		List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
		
		JMenuItem jMenuItem = new JMenuItem("send to JS Unicode Decoder");
		listMenuItems.add(jMenuItem);
		
		jMenuItem.addActionListener(new ActionListener() {
			Dialog dlg = new Dialog();
			@Override
			public void actionPerformed(ActionEvent e) {
        byte ctx = invocation.getInvocationContext();
        boolean isRequest = (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
            || ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
        IHttpRequestResponse requestResponses = invocation.getSelectedMessages()[0];

        String text =  null;
        String error =  null;
        try {
          text = new String(isRequest ? requestResponses.getRequest() : requestResponses.getResponse(), "UTF-8");
          text = text.substring(start, end);
        } catch (UnsupportedEncodingException ex) {
          error = "Text is not UTF-8 encoded.";
        }

        if (text != null) {
          try {
            text = BurpExtender.decode(text);
          } catch (Exception ex) {
            error = ex.getMessage();
            ex.printStackTrace(BurpExtender.errorStream);
          }
        }

        dlg.setString(text != null ? text : error);
        dlg.setVisible(true);
			}
		});
		
		return listMenuItems;
	}
	
	

}
