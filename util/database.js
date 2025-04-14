const mysql=require('mysql2');

const pool=mysql.createPool({
    host:'localhost',
    user:'root',
    database:'collage',
    password:'Wj28@krhps'
});
module.exports=pool.promise();