function clearTable() {
            const tableBody = document.querySelector('#data-table tbody');
            tableBody.innerHTML = '';
        }

function updatestate(state){
    document.getElementById("oh").innerHTML=state;
}



function host_disc(){
    var ip = document.getElementById("ip").value
    var mask = document.getElementById("mask").value
    clearTable()
    updatestate("working...")
    fetch("http://127.0.0.1:5000/host-discovery/"+ip+"/"+mask)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                      const row = document.createElement('tr');

                      const cell1 = document.createElement('td');
                      cell1.textContent = item.ip;
                      row.appendChild(cell1);

                      const cell2 = document.createElement('td');
                      cell2.textContent = item.mac;
                      row.appendChild(cell2);
                      tableBody.appendChild(row);
                      updatestate("output")
                  });
              })
              .catch(error =>updatestate("bad request"));
}


function port_scan(){
    var ip = document.getElementById("ip").value
    var startport = document.getElementById("startport").value
    var endport = document.getElementById("endport").value
    var scantype = document.getElementById("scantype").value
    clearTable()
    updatestate("working...")
    fetch("http://127.0.0.1:5000/portscan/" +ip+ "/" + startport +"/" +endport+ "/" + scantype)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                      const row = document.createElement('tr');

                      const cell1 = document.createElement('td');
                      cell1.textContent = item.port;
                      row.appendChild(cell1);

                      const cell2 = document.createElement('td');
                      cell2.textContent = item.service;
                      row.appendChild(cell2);


                      const cell3 = document.createElement('td');
                      cell3.textContent = item.state;
                      row.appendChild(cell3);
                      tableBody.appendChild(row);

                      updatestate("output")
                  });
              })
              .catch(error => updatestate("bad request"));
}


function trac(){
    var ip = document.getElementById("ip").value

    clearTable()
    updatestate("working...")
    fetch("http://127.0.0.1:5000/traceroute/" +ip)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                      const row = document.createElement('tr');

                      const cell1 = document.createElement('td');
                      cell1.textContent = item.id;
                      row.appendChild(cell1);

                      const cell2 = document.createElement('td');
                      cell2.textContent = item.ip;
                      row.appendChild(cell2);


                      tableBody.appendChild(row);

                      updatestate("output")
                  });
              })
              .catch(error => updatestate("bad request"));
}



function brut() {
  var ip = document.getElementById("ip").value;
  var username = document.getElementById("username").value;
  var service = document.getElementById("service").value;
  updatestate("working...");
  fetch("http://127.0.0.1:5000/bruteforce/" + ip + "/" + service + "/" + username, {
    method: "POST",
    body: JSON.stringify(data)
  })
    .then(response => response.json())
    .then(data => {
      data.forEach(item => {
        updatestate("result: "+ item.password);
      });
    })
    .catch(error => updatestate("bad request"));
}


function flood() {
  var ip = document.getElementById("ip").value;
  var port = document.getElementById("port").value;
  var amount = document.getElementById("amount").value;
  var size = document.getElementById("size").value;
  var type = document.getElementById("type").value;
  updatestate("working...");
  fetch("http://127.0.0.1:5000/flood/" + ip + "/" + port + "/" + type + "/" + amount + "/" + size)
    .then(response => response.json())
    .then(data => {
      data.forEach(item => {
        updatestate("attacked: "+ item.attacked);
      });
    })
    .catch(error => updatestate("bad request"));
}

function psni(){
    var interface = document.getElementById("interface").value
    var duration = document.getElementById("duration").value

    clearTable()
    updatestate("working...")
    fetch("http://127.0.0.1:5000/packetsniffer/" +interface+"/"+duration)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                      const row = document.createElement('tr');

                      const cell1 = document.createElement('td');
                      cell1.textContent = item.protocol;
                      row.appendChild(cell1);

                      const cell2 = document.createElement('td');
                      cell2.textContent = item.sip;
                      row.appendChild(cell2);

                      const cell3 = document.createElement('td');
                      cell3.textContent = item.dip;
                      row.appendChild(cell3);

                      const cell4 = document.createElement('td');
                      cell4.textContent = item.sport;
                      row.appendChild(cell4);

                      const cell5 = document.createElement('td');
                      cell5.textContent = item.dport;
                      row.appendChild(cell5);

                      const cell6 = document.createElement('td');
                      cell6.textContent = item.payload.substring(0, 20);
                      row.appendChild(cell6);


                      tableBody.appendChild(row);

                      updatestate("output")
                  });
              })
              .catch(error => updatestate("bad request"));
}

function pingofdeath(){
    var ip = document.getElementById("ip").value

    updatestate("working...")
    fetch("http://127.0.0.1:5000/pingofdeath/" +ip)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                       updatestate("attacked: "+ item.attacked);
                  });
              })
              .catch(error => updatestate("bad request"));
}

function dhcps(){
    var time = document.getElementById("duration").value

    updatestate("working...")
    fetch("http://127.0.0.1:5000/dhcpstarvation/" +time)
              .then(response => response.json())
              .then(data => {
                  const tableBody = document.querySelector('#data-table tbody');
                  data.forEach(item => {
                       updatestate("attacked for: "+ item.t);
                  });
              })
              .catch(error => updatestate("bad request"));
}