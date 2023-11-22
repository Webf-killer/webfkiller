var mysql      = require('mysql');
var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : '1111',
  database : 'mydb2'
});

connection.connect();

connection.query('SELECT * from PACKETDATA', function (error, results, fields) {
  if (error) throw error;
  console.log(results);
});

connection.end();
