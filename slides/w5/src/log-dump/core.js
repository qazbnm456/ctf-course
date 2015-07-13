
var pc = 0;
var inst_eip_offset = 15;
var highlight_value;
var is_highlight = 0;
var stack_view_yoff = 0;
var display_type = 0;

function highlight_on(value){
  highlight_value = value;
  is_highlight = 1;
  render();
}

function highlight_off(){
  is_highlight = 0;
  render();
}

function highlight_match(value){
  if(is_highlight==0) return 0;
  return value==highlight_value;
}

function render_mem(){
  var p = 0;
  var mem_lines = new Array();
  var addrs = new Array();
  for (var x in states[pc]['memory']){
    m = states[pc]['memory'][x];
    x = parseInt(x);
    for (var i=0; i<m.length; i++){
      var y = m[i];
      for (var j=0; j<4; j++) {
        mem_lines.push({"index":p,"address":x+i*4+j,"value":(y&0xff)});
        y>>=8;
        p++;
      }
      if (i%4==0){
        addrs.push(x+i*4);
      }
    }
    p = (p+15)&0xfffffff0;
  }
  var gml = gm.selectAll("#value")
    .data(mem_lines);
  gml.enter().append("text")
    .attr("id", "value")
    .attr("font-family","Monaco")
    .attr("font-size", 18)
    .attr("x", function(d) { return (d.index%16)*28+100;})
    .attr("y", function(d) { return Math.floor(d.index/16)*24+24;});
  gml.transition()
    .text(function(d) { 
      if (display_type==1) {
        return String.fromCharCode(d.value);
      }else {
        return ("00"+d.value.toString(16)).slice(-2).toUpperCase() 
      }
    });
  gml.exit().remove();
  gml = gm.selectAll("#address")
    .data(addrs)
    .enter().append("text")
    .attr("id", "address")
    .attr("font-family","Monaco")
    .attr("font-size", 18)
    .attr("x", 0)
    .attr("y", function(d,i) { return i*24+24})
    .text(function(d) { return ("00000000"+d.toString(16)).slice(-8).toUpperCase() });
}

function render_reg() {
  var reg_list = new Array();
  m = states[pc]['regs'];
  reg_list.push({"name":"eax","value":m['eax']});
  reg_list.push({"name":"ecx","value":m['ecx']});
  reg_list.push({"name":"edx","value":m['edx']});
  reg_list.push({"name":"ebx","value":m['ebx']});
  reg_list.push({"name":"esp","value":m['esp']});
  reg_list.push({"name":"ebp","value":m['ebp']});
  reg_list.push({"name":"esi","value":m['esi']});
  reg_list.push({"name":"edi","value":m['edi']});

  grr = gr.selectAll('#bg').data(reg_list);

  gre = grr.enter().append('g')
    .attr('id', 'bg')
    .attr("transform", function(d, i) { return "translate(0,"+(i*25)+")"; })
    .on('click',
        function(d,i) {
          highlight_on(d.value);
        }
       );

  grr.exit().remove();

  gre.append('rect')
    .attr('x', 0)
    .attr('y', 0)
    .attr('width', 160)
    .attr('height', 25)
    .attr('fill', "white");
  grr.transition().select('rect')
    .attr('fill',
        function(d){
          console.log(d.value);
          if(highlight_match(d.value)){
            return '#FF0';
          }else{
            return '#FFF';
          }
        }
        );
  gre.append('text')
    .attr("x", 10)
    .attr("y", 20)
    .attr("font-family","Monaco")
    .attr("font-size", 18)
    .text(function(d) { return d.name + ": " +
      ("00000000"+d.value.toString(16)).slice(-8).toUpperCase() });
  grr.transition().select('text')
    .text(function(d) { return d.name + ": " +
      ("00000000"+d.value.toString(16)).slice(-8).toUpperCase() });

}

function render() {

  var b,t;
  // Inst
  var inst_view = gi.selectAll("#inst")
    .data(inst_list, function(d) { return d.index; });
  var inst_view_height = 24;
  function inst_bg(d) {
    return d.index==inst_head+inst_eip_offset?"#0FF":"#FFF";
  }
  function inst_label(d){
    var inst = d.inst;
    var j = inst[0].indexOf('<');
    var k = inst[0].indexOf('>');
    if (j==-1) return "";
    return inst[0].substr(j, k-j+1);
  }
  function inst_text(d){
    var inst = d.inst;
    var j = inst[0].indexOf(' ');
    if (j==-1){
      var addr = inst[0].substr(2);
    } else {
      var addr = inst[0].substr(2,j-2);
    }
    var aa = addr + ": " + inst[1];
    var l = inst_label(d);
    var ll = 65 - l.length;
    aa = aa+"                                                                        ";
    return aa.substr(0,ll+1)+l;
  }

  b = inst_view.enter().append("g")
    .attr("id", "inst")
    .attr("transform", function(d, i) { return "translate(0,"+(i*inst_view_height)+")"; });
  t = inst_view.transition()
    .attr("transform", function(d, i) { return "translate(0,"+(i*inst_view_height)+")"; });

  t.selectAll("rect")
    .attr("fill", inst_bg);
  t.selectAll("text")
    .text(inst_text);
  inst_view.exit().remove();
  b
    .on("mouseover", 
        function(d) {
          d3.select(this).select("rect").attr("fill", "yellow");
        }
       ) 
    .on("mouseout", 
        function(d) {
          d3.select(this).select("rect").attr("fill", inst_bg);
        }
       );
  b.append("rect")
    .attr("fill", inst_bg)
    .attr("width", 720)
    .attr("height", inst_view_height);
  b.append("text")
    .attr("x", 0)
    .attr("y", 20)
    .attr("font-family", "Monaco")
    .attr("font-size", "18px")
    .attr("xml:space", "preserve")
    .text(inst_text);

  // Stack
  gsc.transition().attr("y", -stack_view_yoff+30);
  gs.transition()
    .attr("transform", function(d, i) { return "translate(20,"+stack_view_yoff+")"; });
  var stack_view = gs.selectAll("#stack")
    .data(stack_value, function(d) { return d.address; });
  var stack_view_height = 24;

  b = stack_view.enter().append("g")
    .attr("id", "stack")
    .attr("transform", function(d, i) { return "translate(0,"+(i*stack_view_height)+")"; });

  var tb = stack_view.transition()
    .attr("transform", function(d, i) { return "translate(0,"+(i*stack_view_height)+")"; });
  tb.select("text")
    .attr("fill", function(d) { return d.address<states[pc]['regs']['esp']?"#ccc":"#000"; })
    .text(function(d){ 
      if (display_type==0) {
        return sprintf("%08X: %08X", d.address, d.value); 
      } else {
        return sprintf("%08X: %c %c %c %c", d.address, 
          d.value&0xff, (d.value>>8)&0xff, (d.value>>16)&0xff, (d.value>>24)&0xff); 
      }
    }
    );

  tb.select("rect")
    .attr('fill',
        function(d){
          if(highlight_match(d.address)||highlight_match(d.value)){
            return '#FF0';
          }else{
            return '#FFF';
          }
        }
        );

  b.append("rect")
    .attr("fill", 'white')
    .attr("stroke", "#ccc")
    .attr("width", 220)
    .attr("height", stack_view_height);

  b.insert("text")
    .attr("x", 10)
    .attr("y", 20)
    .attr("font-family", "Monaco")
    .attr("font-size", "18px")
    .attr("fill", function(d) { return d.address<states[pc]['regs']['esp']?"#ccc":"#000"; })
    .text(function(d){ 
      if (display_type==0) {
        return sprintf("%08X: %08X", d.address, d.value); 
      } else {
        return sprintf("%08X: %c %c %c %c", d.address, 
          d.value&0xff, (d.value>>8)&0xff, (d.value>>16)&0xff, (d.value>>24)&0xff); 
      }
    }
    );



  stack_view.exit().remove();

  render_mem();
  render_reg();
}

function resize() {
  width = window.innerWidth, height = window.innerHeight;
  g.attr("width", 1024).attr("height", height)
    .style("margin-left", (width - 1024)/2);
  render();
}

function update_stack() {
  esp = states[pc]['regs']['esp'];
  for (var i=0; i<stack_size; i++) {
    stack_value[i] = {"address": esp+i*4-40,"value":states[pc]['stack'][i]};
  }
}

function update_inst() {
  eip = states[pc]['regs']['eip'];
  inst_head = inst_a2i[eip] - inst_eip_offset;
  if (inst_head<0) inst_head = 0;
  for (var i=0; i<inst_list.length; i++) {
    inst_list[i] = {"index": inst_head + i, "inst": inst_i2c[inst_head+i]};
  }
}

function update() {
  update_stack();
  update_inst();
  render();
  //highlight_off();
}

function si() {
  if (pc<states.length-1) {
    pc++;
    update();
  }
}

function rsi() {
  if (pc>0) {
    pc--;
    update();
  }
}

function ni() {
  if (states[pc]['ni']!=-1) {
    pc = states[pc]['ni'];
    update();
  }
}

function rni() {
  if (states[pc]['rni']!=-1) {
    pc = states[pc]['rni'];
    update();
  }
}

function fin() {
  if (states[pc]['fin']!=-1) {
    pc = states[pc]['fin'];
    update();
  }
}

function pret() {
  if (states[pc]['pret']!=-1) {
    pc = states[pc]['pret'];
    update();
  }
}

function nret() {
  if (states[pc]['nret']!=-1) {
    pc = states[pc]['nret'];
    update();
  }
}


function init() {
  g = d3.select("body").append("svg");
  gsc = g.append("defs").append("clipPath")
    .attr("id", "stack-view-clip")
    .append("rect")
    .attr("x", 0)
    .attr("y", 30)
    .attr("width", 220)
    .attr("height", 610);
  g.append("defs").append("clipPath")
    .attr("id", "inst-view-clip")
    .append("rect")
    .attr("x", 0)
    .attr("y", 200)
    .attr("width", 720)
    .attr("height", 400);
  gi = g.append("g")
    .attr("id", "inst-view")
    .attr("clip-path", "url(#inst-view-clip)")
    .attr("transform", function(d, i) { return "translate(260,40)"; });
  gs = g.append("g")
    .attr("id", "stack-view")
    .attr("clip-path", "url(#stack-view-clip)")
    .attr("transform", function(d, i) { return "translate(20,30)"; });
  gm = g.append("g")
    .attr("id", "mem-view")
    .attr("transform", function(d, i) { return "translate(260,30)"; });
  gm.append("rect")
    .attr("x", 0)
    .attr("y", 0)
    .attr("fill", "white")
    .attr("width", 550)
    .attr("height", 200);
  gr = g.append("g")
    .attr("id", "reg-view")
    .attr("transform", function(d, i) { return "translate(820,30)"; });
  gr.append("rect")
    .attr("x", 0)
    .attr("y", 0)
    .attr("fill", "cyan")
    .attr("width", 160)
    .attr("height", 200);
  g.append("rect")
    .attr("x", 260)
    .attr("y", 240)
    .attr("width", 720)
    .attr("height", 400)
    .attr("fill", "none")
    .attr("stroke", "#000");
  g.append("rect")
    .attr("x", 260)
    .attr("y", 30)
    .attr("width", 550)
    .attr("height", 200)
    .attr("fill", "none")
    .attr("stroke", "#000");
  g.append("rect")
    .attr("x", 820)
    .attr("y", 30)
    .attr("width", 160)
    .attr("height", 200)
    .attr("fill", "none")
    .attr("stroke", "#000");
  g.append("rect")
    .attr("x", 20)
    .attr("y", 30)
    .attr("width", 220)
    .attr("height", 610)
    .attr("fill", "none")
    .attr("stroke", "#000");


  pc = 0;
  stack_size = states[0]['stack'].length;
  stack_value = new Array(stack_size);
  inst_head = 0;
  inst_list = new Array(30);

  update();

  d3.select("body")
    .on("keydown", function() {
      switch (d3.event.keyCode) {
        case 219: //[
          pret();
          break;
        case 221: //]
          nret();
          break;
        case 90: //Z
          if (stack_view_yoff>-800){
            stack_view_yoff-=100;
            render();
          }
          break;
        case 81: //Q
          if (stack_view_yoff<0){
            stack_view_yoff+=100;
            render();
          }
          break;
        case 37: //left
          rsi();
          break;
        case 38: //up
          rni();
          break;
        case 39: //right
          si();
          break;
        case 40: //down
          ni();
          break;
        case 27: //Esc
          fin();
          break;
        case 32:
          display_type = 1-display_type;
          render();
          break;
        default:
      }
    });

  d3.select(window).on("resize", resize);
  resize();
}

init();

