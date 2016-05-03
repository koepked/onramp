// Select all elements with data-toggle="tooltips" in the document
$('[data-toggle="tooltip"]').tooltip();
$('.collapse').collapse();

function workspaceModule(data){
	var self = this;
	self.id = data['module_id'];
	self.name = data['module_name'];
	self.desc = data['description'];
	self.formFields = ko.observableArray();
	self.PCEs = ko.observableArray();
	self.formInfo = ko.observableArray();
	console.log("CHRISTA DESC: " + self.desc);

	self.addDefaultFormFields = function () {
		this.formFields.push({"field": "name", "value": "test"});
		this.formFields.push({"field": "nodes", "value": 1});
		this.formFields.push({"field": "processes", "value": 4});
	}


	self.getRealFormFields = function (pce_id) {
		self.formFields.removeAll();
		//self.formFields.push({"field":"job_name","value":"new job"});
		$.getJSON( sessionStorage.server + "/pces/" + pce_id + "/module/" + self.id + "?apikey=" + JSON.parse(sessionStorage['auth_data']).apikey,
			function (data){
				// {"status": 0,
				//  "status_message": "Success",
				//  "users": {
				//    "fields": ["user_id", "username", "full_name", "email", "is_admin", "is_enabled"],
				//    "data": [2, "alice", "", "", 0, 1]}}
			       var raw = data.pces;
			       console.log("stuff from pce mod: ");
			       console.log(raw);

				var raw = data.pces.uioptions;
				//console.log(raw);

				var raw = data.pces.uioptions.onramp;
				//console.log(raw);
				
				/*
				if(self.name == "mpi-ring"){
					var raw = data.pces.uioptions["ring"];
					console.log(raw);
				}
				else if(self.name == "template"){
					var raw = data.pces.uioptions["hello"];
					console.log(raw);
				}
				else {
					var raw = data.pces.uioptions[self.name];
					console.log(raw);
				}
				*/


				/*
				var onramp_fields = [{"field":"job_name", "value":""}];
				data.pces.uioptions.onramp.forEach(function (item, index, array){
					onramp_fields.push({"field":item, "value":""});
					});
				self.formFields.push({"onramp":onramp_fields});

				var my_fields = [];
				data.pces.uioptions[self.name].forEach(function (item, index, array){
					my_fields.push({"field":item, "value":""});
				});
				var name = self.name.toString();
				self.formFields().push({name : my_fields});
				self.formFields().forEach(function (item, index, array) {"* " + console.log(item);});
				*/

				self.formFields.push({field:"job_name", data:""});
				data.pces.uioptions.onramp.forEach(function (item, index, array){
					self.formFields.push({field:"onramp " + item, data:""});
					self.formInfo.push({formid: item});
				});

				if(self.name == "mpi-ring"){
					data.pces.uioptions["ring"].forEach(function (item, index, array){
						self.formFields.push({field:"ring " + item, data:""});
						self.formInfo.push({formid: item});
						console.log("christa"+ item);
					});
				}
				else if(self.name == "template" || self.name == "monte-carlo"){
					data.pces.uioptions["hello"].forEach(function (item, index, array){
						self.formFields.push({field:"hello " + item, data:""});
						self.formInfo.push({formid: item});
						console.log("christa"+ item);
					});
				}
				else {
					data.pces.uioptions[self.name].forEach(function (item, index, array){
						self.formFields.push({field:self.name + " " + item, data:""});
						self.formInfo.push({formid: item});
						console.log("christa"+ item);
					});
				}

				console.log("added fields!");
				console.log(self.formFields());
				//call method to set the ids of each label
				setFormId(self.formInfo());
			}
		);
	}
}

//forEach(<instance> in <objects>)
var setFormId = function(formInfo){
	var formID = "";
	var labels = document.getElementsByTagName("label");
		for(var i = 1; i < labels.length; i++){
			formID = formInfo[i-1].formid;
		   labels[i].setAttribute("id", formID);
		   var myDescription = getDescription(formID);
	
		   //http://stackoverflow.com/questions/22044106/display-tooltip-on-labels-hover
		   //create the popup look at this: http://stackoverflow.com/questions/3559467/description-box-on-mouseover
		   
		   //<span id="helpBlock" class="help-block">A block of help text that breaks onto a new line and may extend beyond one line.</span>
			if( myDescription !== "none"){
			   /*var span = document.createElement("span");
			   span.setAttribute("class", "help-block");
			   var myDescription = getDescription(formID);
			   var description = document.createTextNode(myDescription);
			   span.appendChild(description);
			   $(span).insertAfter(labels[i]);
			   $(footdiv).append("<button type=\"button\" class=\"btn btn-primary\" onclick= newGame()>New Game</button>");*/
			    var myDescription = getDescription(formID);
			   $(labels[i]).append("<span style = \"display:block;font-size:80%\" class = \"help-block\"><span class = \"glyphicon glyphicon-info-sign\"></span> "+myDescription+"</span>");
			}

		}
}
/*maybe put in placeholder for the default*/

var getDescription = function( formID ){
	var description = "";
	if(formID === "rectangles"){
		description = "Number of rectangles for the Riemann Sum. Default = 100000000";
	}
	else if(formID === "threads"){
		description = "Number of OpenMP threads to use for each process. Default = 1";
	}
	else if(formID === "mode"){
		description = "Version of program to run ('s' -> serial, 'o' -> openmp, 'm' -> mpi, 'h' -> hybrid). Default = s";
	}
	else if(formID === "np"){
		description = "Number of processes";
	}
	else if(formID === "nodes"){
		description = "Number of nodes";
	}
	else{
		description = "none";
	}
	return description;
}

var openModuleModal = function(){
	$('#moduleModal').modal('show');
}

var openPCEModal = function(){
	$('#PCEModal').modal('show');
}

//forEach(instance in objects)
//use this to create a pop up somehow
/*var displayConcepts = function(btn){
	
	//FIGURE OUT HOW TO CLOSE THE DIV BY CLICKING ON THE BUTTON AGAIN. COULD DO A COUNT? BASICALLY A 1 OR 0 THAN SWITCHES
	var childClass = $(btn).next().className;
	console.log("christa childClass = " + childClass);
	
	//because of the button calling this method you can't click the button to make the concepts div disapper because it will hit the below two lines
	$(".info-div").removeClass("info-notActive"); //make 
	$(".info-div").addClass("info-isActive");
		
	//check for white space click
	$(document).mouseup(function (e){
		var container = $(".info-div");

		if (!container.is(e.target) // if the target of the click isn't the container...
			) // ... nor a descendant of the container
		{
			$(".info-div").removeClass("info-isActive"); //make 
			$(".info-div").addClass("info-notActive");
		}
	});

}*/


function myWorkspace(data){
	var self = this;
	self.id = data['workspace_id'];
	self.name = data['workspace_name'];
	self.desc = data['description'];
	console.log("CHRISTA DESC: " + self.desc);


	self.captureWSID = function () {

		localStorage.setItem("WorkspaceID", self.id);
		alert("workspa e " + localStorage.getItem('WorkspaceID'));
		window.location.href = "workspace.html";
		return;
	}
}


function OnrampWorkspaceViewModel () {
	// Data
	var self = this;
	self.userID = sessionStorage['UserID'];
	self.auth_data = sessionStorage['auth_data'];
	self.workspaceID = sessionStorage['WorkspaceID'];
	self.workspaceInfo = ko.observable();
	//self.workspaceInfo(new Workspace({'WorkspaceID': 1,
	//'WorkspaceName': 'default',
	//'Description':'My personal workspace'}));

	self.username = JSON.parse(self.auth_data).username;

	self.PCElist = ko.observableArray();
	self.Jobslist = ko.observableArray();
	self.Modulelist = ko.observableArray();

	self.allPCEs = [];
	self.allModules = [];

	self.welcome1 = ko.observable("not loaded yet");

	self.selectedPCE = ko.observable();
	self.selectedModule = ko.observable();


	$(document).ready( function () {
		// get data from server
		$.getJSON( sessionStorage.server + "/workspaces/" + self.workspaceID + "?apikey=" + JSON.parse(self.auth_data).apikey,
			function (data){
				// {"status": 0,
				//  "status_message": "Success",
				//  "users": {
				//    "fields": ["user_id", "username", "full_name", "email", "is_admin", "is_enabled"],
				//    "data": [2, "alice", "", "", 0, 1]}}
				var raw = data.workspaces.data;
				console.log(raw);
				var conv_data = {};
				for(var i = 0; i < data.workspaces.fields.length; i++){
					console.log("adding: " + data.workspaces.fields[i] + " = " + raw[i]);
					conv_data[data.workspaces.fields[i]] = raw[i];
				}
				self.workspaceInfo(new myWorkspace(conv_data));
				self.welcome1(self.username + "'s " + self.workspaceInfo().name + " workspace");
			}
		);

		$.getJSON( sessionStorage.server + "/workspaces/" + self.workspaceID + "/pcemodulepairs?apikey=" + JSON.parse(self.auth_data).apikey,
		//self.auth_data,
			function (data){
				// {"status": 0,
				//  "status_message": "Success",
				//  "users": {
				//    "fields": ["user_id", "username", "full_name", "email", "is_admin", "is_enabled"],
				//    "data": [2, "alice", "", "", 0, 1]}}
				console.log(JSON.stringify(data));
				var pairs = data.workspaces.data;
				var fields = data.workspaces.fields;
				var setOfPCEIDs = [];
				var setOfModIDs = [];
				for(var i = 0; i < pairs.length; i++){
					self.pce = pairs[i][0];
					self.mod = pairs[i][2];
					// get data for new pce and/or module
					console.log("PCE - Mod id pair: " + self.pce + " - " + self.mod);
					if(setOfPCEIDs.indexOf(self.pce) == -1){
						setOfPCEIDs.push(self.pce);
					}
					if(setOfModIDs.indexOf(self.mod) == -1){
						setOfModIDs.push(self.mod);
					}
				}

				// get data for the set of PCEs
				for(var i = 0; i < setOfPCEIDs.length; i++){
					$.getJSON(sessionStorage.server + "/pces/" + setOfPCEIDs[i] + "?apikey=" + JSON.parse(self.auth_data).apikey,
						function(data){
							var raw = data.pces.data;
							console.log(raw);
							var conv_data = {};
							for(var j = 0; j < data.pces.fields.length; j++){
								console.log("adding: " + data.pces.fields[j] + " = " + raw[j] + " (" + (raw[j] + 1 ) + ")");
								conv_data[data.pces.fields[j]] = raw[j];
							}
							var newpce = new PCE(conv_data, false);
							for(var j = 0; j < pairs.length; j++){
								var p = pairs[j][0];
								var m = pairs[j][2];
								if(p == raw[0]){
									newpce.modules.push(m);
								}
							}
							self.allPCEs.push(newpce);
							self.PCElist.push(newpce);
						}
					);
				}

				// get data for the set of Modules
				for(var i = 0; i < setOfModIDs.length; i++){
					$.getJSON(sessionStorage.server + "/modules/" + setOfModIDs[i] + "?apikey=" + JSON.parse(self.auth_data).apikey,
						function(data){
							var raw = data.modules.data;
							console.log(raw);
							var conv_data = {};
							for(var j = 0; j < data.modules.fields.length; j++){
								console.log("adding: " + data.modules.fields[j] + " = " + raw[j]);
								conv_data[data.modules.fields[j]] = raw[j];
							}
							var newmod = new workspaceModule(conv_data);
							for(var j = 0; j < pairs.length; j++){
								var p = pairs[j][0];
								var m = pairs[j][2];
								if(m == raw[0]){
									newmod.PCEs.push(p);
								}
							}
							// need to replace with real form fields
							//newmod.addDefaultFormFields();
							self.allModules.push(newmod);
							self.Modulelist.push(newmod);
						}
					);
				}
			}
		);
	});



	// Behaviors
	self.selectPCE = function (PCE) {
		self.selectedPCE(PCE);
		console.log("Selected PCE: " + PCE.name + " (" + PCE.modules().length + ")");
		//self.selectedModule(null);
		if(! self.selectedModule()){
			self.Modulelist.removeAll();
			for(var i = 0; i < PCE.modules().length; i++){
				console.log("Adding module id " + PCE.modules()[i] );
				var mm = self.findById(self.allModules, PCE.modules()[i])
				if(mm){
					self.Modulelist.push(mm);
				}
				else {
					console.log("can't find module id " + (PCE.modules()[i] + 1));
				}
			}
		}
		else {
			// module and pce selected
			console.log("<<<getting form fields>>>");
			self.selectedModule().getRealFormFields(PCE.id);
		}
		self.selectedPCE(PCE);
	}

	self.selectModule = function (m) {
		self.selectedModule(m);
		console.log("Selected Module: " + self.selectedModule().name);
		console.log(" (" + self.selectedModule().PCEs().length + ")");
		if(! self.selectedPCE()){
			self.PCElist.removeAll();
			for(var i = 0; i < self.selectedModule().PCEs().length; i++){
				console.log("Adding pce id " + self.selectedModule().PCEs()[i] );
				self.PCElist.push(self.findById(self.allPCEs, self.selectedModule().PCEs()[i]));
			}
		}
		else {
			// module and pce selected
			console.log("????getting form fields???");
			m.getRealFormFields(self.selectedPCE().id);
		}
		self.selectedModule(m);
	}


	self.changePCE = function () {

		//self.selectedModule(null);
		// display all PCEs
		self.PCElist.removeAll();
		if(self.selectedModule()){
			console.log("Changing PCE, selected module is $$$$$" + self.selectedModule().name);
			for(var i = 0; i < self.selectedModule().PCEs().length; i++){
				self.PCElist.push(self.findById(self.allPCEs, self.selectedModule().PCEs()[i]));
			}
		}
		else {
			console.log("Changing PCE, selected module is null");
			self.Modulelist.removeAll();
			for(var i = 0; i < self.allPCEs.length; i++){
				self.PCElist.push(self.allPCEs[i]);
			}
			for(var i = 0; i < self.allModules.length; i++){
				console.log("adding module " + self.allModules[i] + " to the list");
				self.Modulelist.push(self.allModules[i]);
			}
		}
		self.selectedPCE(null);
	}

	self.changeModule = function () {

		self.Modulelist.removeAll();
		if(self.selectedPCE()){
			console.log("Changing module, $$$$selected PCE is " + self.selectedPCE().name );
			for(var i = 0; i < self.selectedPCE().modules().length; i++){
					self.Modulelist.push(self.findById(self.allModules, self.selectedPCE().modules()[i]));
			}
		}
		else{
			self.PCElist.removeAll();
			console.log("Changing module, selected PCE is null" );
			for(var i = 0; i < self.allModules.length; i++){
				console.log("adding module " + self.allModules[i] + " to the list");
				self.Modulelist.push(self.allModules[i]);
			}
			for(var i = 0; i < self.allPCEs.length; i++){
				self.PCElist.push(self.allPCEs[i]);
			}
		}
		self.selectedModule(null);
	}


	this.launchJob = function(formData){
		console.log("launching job");
// 		{
//     "auth": {
//         ... // Removed for brevity
//     },
//     "info": {
//         "job_name": "Run Alpha 2",
//         "module_id": 1,
//         "pce_id": 1,
//         "user_id": 2,
//         "workspace_id": 1
//     },
//     "uioptions": {
//         "onramp": {
//             "nodes": 1,
//             "np": 2
//         },
//         "ring": {
//             "iters": 5,
//             "work": 1
//         }
//     }
// }
		// construct uioptions
		var opts = {"onramp":{}};
		var mod_name = self.selectedModule().name;
		if(self.selectedModule().name == "mpi-ring"){
			mod_name = "ring";
		}
		else if (self.selectedModule().name == "template"){
			mod_name = "hello";
		}
		opts[mod_name] = {};
		formData.formFields().forEach( function(item, index, array){
			
			if(item.field != "job_name"){
				if(item.field.search("onramp") >= 0){
					// get onramp fields
					console.log(item.field.slice(7));
					opts["onramp"][item.field.slice(7)] = item.data;
				}
				else if(item.field.search(mod_name) >= 0){
					console.log(item.field.slice("CHRISTA: "+mod_name.length + 1));
					opts[mod_name][item.field.slice(mod_name.length + 1)] = item.data;
				}
				else {
					console.log("badness!!!");
				}
			}
			else {
				console.log(index + ") " + item.field + " : " + item.data);
			}
		});
		console.log(formData.formFields()[0].data);
		

		var data_packet = JSON.stringify({
			"auth": JSON.parse(self.auth_data),
			"info": {
				"workspace_id": parseInt(self.workspaceID),
				"module_id" : self.selectedModule().id,
				"pce_id" : self.selectedPCE().id,
				"user_id" : parseInt(self.userID),
				"job_name" : formData.formFields()[0].data
			},
			"uioptions" : opts
		});

		// POST to jobs
		$.ajax({
			type: "POST",
			url: sessionStorage.server + "/jobs?apikey=" + JSON.parse(self.auth_data).apikey,
			data: data_packet,
			complete: function (data){
				// create confirm with job id info
				if(data.status == 200){
					console.log(JSON.stringify(data));
					if(window.confirm("Job created.  ID " + JSON.parse(data.responseText).job.job_id + "\nClick OK to view job results page.  Cancel to stay on this page.")){
						window.location.href = "job_details.html";
					}
					// else do nothing
				}
				else{
					alert("Something went wrong when connecting to the server.  Status code: " + data.status);
				}
			},
			dataType: 'application/json',
			contentType: 'application/json'
		});

	}
/*
this.alpacaForm = function (formData) {
$.alpaca({
"data" : {
"name": "Diego Maradona",
"feedback": "Very impressive.",
"ranking": "excellent"
},
"schema": {
"title":"User Feedback",
"description":"What do you think about Alpaca?",
"type":"object",
"properties": {
"name": {
"type":"string",
"title":"Name"
},
"feedback": {
"type":"string",
"title":"Feedback"
},
"ranking": {
"type":"string",
"title":"Ranking",
"enum":['excellent','ok','so so']
}
}
},
"options": {
"form":{
"attributes":{
"action":"http://httpbin.org/post",
"method":"post"
},
"buttons":{
"submit":{}
}
},
"helper": "Tell us what you think about Alpaca!",
"fields": {
"name": {
"size": 20,
"helper": "Please enter your name."
},
"feedback" : {
"type": "textarea",
"name": "your_feedback",
"rows": 5,
"cols": 40,
"helper": "Please enter your feedback."
},
"ranking": {
"type": "select",
"helper": "Select your ranking.",
"optionLabels": ["Awesome!",
"It's Ok",
"Hmm..."]
}
}
},
"view" : "bootstrap-edit"
});
}*/

// load data from server


// helper functions
self.findById = function (thisList, id){
	for(var i = 0; i < thisList.length; i++){
		if(thisList[i].id == id){
			return thisList[i];

		}
	}
	return null;
}



}


ko.applyBindings(new OnrampWorkspaceViewModel());
