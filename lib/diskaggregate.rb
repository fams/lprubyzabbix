
class DiskAggregate
  def initialize(api_connection,sender_connection)
    @api_connection= api_connection
    @sender_connection = sender_connection
    
  end
  def host_update(hostobj)
    #@host="Zabbix server" 
    @host=hostobj["host"]
    @hostid=hostobj["hostid"]
    #binding.pry
    #GetHostID
    # @hostid = hostobj["hostid"]
    #@hostid = zbx.hosts.get_id( :host => @host )
    #Lista Items no host, filtra os que são de filesystes, retorna os items e valores para cálculo
    #@items = @api_connection.query(
      #:method => "item.getobjects",
      #:params => { 
      #    :output =>  "extend",
      #    :host => @host
    @items = @api_connection.query(
      :method => "item.get",
      :params => { 
          :output =>  "extend",
          :hostids => @hostid
      }
    
    ).find_all { |e| e["key_"].start_with?("vfs.fs.size") }.map {|i| {:itemid => i["itemid"],:key=> i["key_"],:lastvalue=>i["lastvalue"]}}
   # resul = @api_connection.query(
   #   :method => "item.get",
   #   :params => { 
   #       :output =>  "extend",
   #       :hostids => @hostid
   #   }
   # )
    #binding.pry 
    #Uso de disco e total de disco
    total=@items.find_all {|i| i[:key].end_with?("total]") }.map{|e| e[:lastvalue].to_i}.inject(:+)
    used=@items.find_all {|i| i[:key].end_with?("used]") }.map{|e| e[:lastvalue].to_i}.inject(:+)
    #Atualiza o Host
    pp @sender_connection.to(@host) {
      send 'vfs.aggregate[,total]',  total
      send 'vfs.aggregate[,used]',  used
    }
    #binding.pry 
  end
  ###################START HERE###########
  #Recupera ID do Template
  def template_update(template)
  
    @template = @api_connection.templates.get_id(:host => template)
    #Descobre Hosts que tem o template de disco associado
    @api_connection.query(
      :method => "host.get",
      :params  => {
         :output => "extend",
         :templateids => @template
      }
    ).each do |h|
      #Chama metodo de update dos dados do host
      host_update h
    end
  end
end
