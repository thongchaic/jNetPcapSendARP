import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class SendARP {
	
	
    byte []targ_ip = {(byte)192,(byte)168,(byte)9,(byte)120};
    int opcode = 1;//ARP request
    byte sender_ip[] = {(byte)192,(byte)168,(byte)9,(byte)1};
    byte sender_mac[] = {(byte)0x00,(byte)0x21,(byte)0x91,(byte)0x16,(byte)0xc9,(byte)0xb5};
    
    int ifindex = 7;
    
	public void send(){
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder(); 
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());  
            return;  
        }  
        System.out.println("Network devices found:");  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
  
        
        PcapIf device = alldevs.get(ifindex); 
        
        
        
        System.out.printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());
        
    	   int snaplen = 64 * 1024;           
           int flags = Pcap.MODE_PROMISCUOUS; 
           int timeout = 10 * 1000; 
           
           Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
           	
           if (pcap == null) {  
               System.err.printf("Error while opening device for capture: "  
                   + errbuf.toString());  
               return;  
           }  
           
    	   ArpPacket arp = new ArpPacket(sender_ip,sender_mac, targ_ip, ArpPacket.BROADCAST_HW, opcode);
    	  

   			if (pcap.sendPacket(arp.getARPPacket()) != Pcap.OK) {  
   			      	System.err.println(pcap.getErr());  
   			    }else{
   			    	System.out.println("SEND OK!!");
   			}
    	   
	}
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		(new SendARP()).send();
	}

}
