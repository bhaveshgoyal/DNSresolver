
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.xbill.DNS.*;


public class resolver {
	static List<String> root_servers = new ArrayList<String>(Arrays.asList("a.root-servers.net", "b.root-servers.net", "c.root-servers.net"
			, "d.root-servers.net", "e.root-servers.net", "f.root-servers.net"
			, "g.root-servers.net", "h.root-servers.net", "i.root-servers.net"
			, "j.root-servers.net", "k.root-servers.net", "l.root-servers.net"
			, "m.root-servers.net"));
	
	static int q_class = DClass.IN;
	static int q_type = Type.A;
	
	static String query = "google.com";
	public static void main(String[] args) throws IOException {
		
		List<String> curr_lvl_servers = root_servers;
		System.out.println(Name.root);
		if (args.length == 1){
			query = args[0];	
			q_type = Type.A;
		
		}
		else if (args.length == 2){
			query= args[0];
			switch (args[1].toUpperCase()){
				case "A":
					q_type = Type.A;
					break;
				case "MX":
					q_type = Type.MX;
					break;
				case "NS":
					q_type = Type.NS;
					break;
				default:
					System.out.println("DNS Query Type " + args[1] + " not supported.");
					break;
			}
		}
		else
			System.out.println("Invalid Number of arguments. Usage: ./resolver <host-name> [type]");
		
		for(int i = 0; i < args.length; i++)
			System.out.println(args[i]);
		
		for(int i = 0; i < curr_lvl_servers.size(); i++) {
			String r_server = curr_lvl_servers.get(i);
			try {
				SimpleResolver resolver = new SimpleResolver(r_server);
				Name name = Name.fromString(query, Name.root);
				Record record = Record.newRecord(name, q_type, q_class);
				Message msg_q = Message.newQuery(record);
				Message resp = resolver.send(msg_q);
				
				if (resp.toString().contains("status: NOERROR")) {
					System.out.print("Response: " + resp.toString());
					if (resp.getSectionArray(Section.ANSWER).length == 0) {
						curr_lvl_servers = getAuthServers(resp);
						i = 0;
						continue;
					}
					else {
						// Print A Type Record
						Record[] answers = resp.getSectionArray(Section.ANSWER);
						
						for(Record ans_record: answers) {
							if (ans_record.getType() == Type.A) {
								System.out.println("\nANS: " + ans_record.rdataToString());
								return;
							}
							else if (ans_record.getType() == Type.CNAME) {
								System.out.println("\nCNAME found: " + ans_record.rdataToString());
								query = ans_record.rdataToString();
								curr_lvl_servers = root_servers;
								i = 0;
								continue;
							}
						}
					}
				}
				else {
					System.out.println("Response Error:\n" + resp.toString());
				}
			}
			catch(Exception e){
				System.out.println("Query Exception:\n" + e.toString());
			}
		}
	}
	public static List<String> getAuthServers(Message msg) {
		
		List<String> authservers = new ArrayList<String>();
		Record[] authrecs = msg.getSectionArray(Section.AUTHORITY);
		for(Record record: authrecs) {
			authservers.add(strip(record.getAdditionalName().toString()));
		}
		return authservers;
	}
	private static String strip(String str) {
		int size = str.length();
		return str.substring(0, size - 1);
	}
}
