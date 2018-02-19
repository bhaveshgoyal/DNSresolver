
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Date;
import java.lang.System.*;
import java.text.SimpleDateFormat;
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
	static Record[] final_rec;
	static long q_start = 0;
	static long q_end = 0;
	static String when = "";
	public static void main(String[] args) throws IOException {
		
		List<String> curr_lvl_servers = root_servers;
//		System.out.println(Name.root);
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
		
		int i = 0;
		when = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy").format(new Date());
		q_start = System.nanoTime();
		for(;i < curr_lvl_servers.size(); i++) {
			String r_server = curr_lvl_servers.get(i);
			try {
				
                Name name = Name.fromString(query, Name.root);
                Message resp = null;
                try {
                        resp = getResp(r_server, name, q_type);
                }
                catch(Exception e) {
                        try {
                                System.out.println("Socket Timeout Out (" + r_server + "). Retrying DNS Query...");
                                resp = getResp(r_server, name, q_type);
                        }
                        catch (Exception e1) {
                                System.out.println("No response from DNS Query Server " + r_server + ". Trying next (available) server...");
                                throw new SocketTimeoutException();
                        }
                }

				if (resp.toString().contains("status: NOERROR")) {
	//				System.out.print("Response: " + resp.toString());
					if (resp.getSectionArray(Section.ANSWER).length == 0) {
						curr_lvl_servers = getAuthServers(resp);
						i = -1;
						continue;
					}
					else {
						// Print A Type Record
						Record[] answers = resp.getSectionArray(Section.ANSWER);
						
						for(Record ans_record: answers) {
							if (ans_record.getType() == q_type) {
								q_end = System.nanoTime();
								present(resp, q_end - q_start);
								return;
							}
							else if (ans_record.getType() == Type.CNAME) {
								System.out.println("\nCNAME found: " + ans_record.rdataToString());
								query = ans_record.rdataToString();
								curr_lvl_servers = root_servers;
								i = -1;
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
	//			System.out.println("Query Exception:\n" + e.toString());
			}
		}
	}
	public static void present(Message output, long lapsed){
		System.out.println("\nQUESTION SECTION:");

		Record quest = output.getQuestion();
		System.out.println(quest.toString() + "\n");
		
		System.out.println("ANSWER SECTION:");
		
		Record[] answers = output.getSectionArray(Section.ANSWER);
						
		for(Record ans_record: answers) {
			if (ans_record.getType() == q_type) {
				System.out.println(ans_record.toString());
			}
		}
		
		System.out.println("\nQuery Time: " + lapsed/(1000000) + " msec");
		System.out.println("WHEN: " + when);
		System.out.println("MSG SIZE rcvd: " + output.numBytes());
	
	}
	public static List<String> getAuthServers(Message msg) {
		
		List<String> authservers = new ArrayList<String>();
		Record[] authrecs = msg.getSectionArray(Section.AUTHORITY);
		for(Record record: authrecs) {
			if (record.getAdditionalName() != null)
				authservers.add(strip(record.getAdditionalName().toString()));
		}
		return authservers;
	}
	public static Message getResp(String r_server, Name signer, int type) throws IOException {
        SimpleResolver resolver = new SimpleResolver(r_server);
        resolver.setEDNS(0, 0, Flags.DO, null);
        Record record = Record.newRecord(signer, type, q_class);
        Message msg_q = Message.newQuery(record);
        Message resp = resolver.send(msg_q);
        return resp;
    }
	private static String strip(String str) {
		int size = str.length();
		return str.substring(0, size - 1);
	}
}
