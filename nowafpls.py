from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IRequestInfo, IContextMenuInvocation
from javax.swing import JMenuItem, JLabel, JTextField, JOptionPane, JPanel, JFrame
import javax.swing as swing
from java.util import ArrayList
from java.io import ByteArrayOutputStream
import re

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("nowafpls")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_list.add(JMenuItem("Insert Junk Data", actionPerformed=self.insert_junk))
        return menu_list

    def insert_junk(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        selection_bounds = self.context.getSelectionBounds()
        insertion_point = selection_bounds[0] if selection_bounds else len(request)

        options_panel = JPanel()
        options_panel.setLayout(swing.BoxLayout(options_panel, swing.BoxLayout.Y_AXIS))

        junk_sizes_kb = [8, 16, 32, 64, 128, 1024, "Custom"]
        dropdown = swing.JComboBox([str(size) + " KB" if isinstance(size, int) else size for size in junk_sizes_kb])
        
        custom_size_field = JTextField(10)
        custom_size_label = JLabel("Custom size (bytes):")

        custom_size_field.setVisible(dropdown.getSelectedItem() == "Custom")
        custom_size_label.setVisible(dropdown.getSelectedItem() == "Custom")

        options_panel.add(dropdown)
        options_panel.add(custom_size_label)
        options_panel.add(custom_size_field)

        def update_custom_field_visibility(event):
            is_custom_selected = dropdown.getSelectedItem() == "Custom"
            custom_size_label.setVisible(is_custom_selected)
            custom_size_field.setVisible(is_custom_selected)
            if is_custom_selected:
                custom_size_field.requestFocus()
            swing.SwingUtilities.getWindowAncestor(options_panel).pack()

        dropdown.addActionListener(update_custom_field_visibility)

        frame = JFrame()
        dialog = JOptionPane.showConfirmDialog(frame, options_panel, "Select Junk Data Size", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        if dialog == JOptionPane.OK_OPTION:
            selected_size = dropdown.getSelectedItem()
            if selected_size == "Custom":
                try:
                    size_bytes = int(custom_size_field.getText())
                except ValueError:
                    JOptionPane.showMessageDialog(None, "Please enter a valid number for custom size.")
                    return
            else:
                size_bytes = int(selected_size.split()[0]) * 1024

            content_type = self._helpers.analyzeRequest(message).getContentType()
            if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                junk_data = "a=" + "0" * (size_bytes - 2) + "&"
            elif content_type == IRequestInfo.CONTENT_TYPE_XML:
                junk_data = "<!--" + "a" * (size_bytes - 7) + "-->"
            elif content_type == IRequestInfo.CONTENT_TYPE_JSON:
                junk_data = '"junk":"' + "0" * (size_bytes - 10) + '"' + ','
            elif content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
                junk_data = self.create_multipart_junk(request, size_bytes)
            else:
                return

            baos = ByteArrayOutputStream()
            baos.write(request[:insertion_point])
            baos.write(junk_data.encode('utf-8'))
            baos.write(request[insertion_point:])
            message.setRequest(baos.toByteArray())

    def create_multipart_junk(self, request, size):
        request_string = self._helpers.bytesToString(request)
        boundary = re.search(r'boundary=([\w-]+)', request_string)
        if not boundary:
            return ""

        boundary = boundary.group(1)
        junk_field_name = "junk_data"
        
        multipart_structure = (
            "--{0}\r\n"
            "Content-Disposition: form-data; name=\"{1}\"\r\n\r\n"
            "{2}\r\n"
        )
        
        structure_size = len(multipart_structure.format(boundary, junk_field_name, ""))
        junk_data_size = size - structure_size
        junk_data = "0" * junk_data_size

        multipart_junk = multipart_structure.format(boundary, junk_field_name, junk_data)

        return multipart_junk

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass