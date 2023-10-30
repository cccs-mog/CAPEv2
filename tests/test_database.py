# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import os
import shutil
from tempfile import NamedTemporaryFile

import pytest
from sqlalchemy import delete, inspect
from sqlalchemy.exc import SQLAlchemyError

from lib.cuckoo.common.path_utils import path_mkdir
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database, Machine, Tag, Task, TASK_PENDING, TASK_FAILED_ANALYSIS, machines_tags, tasks_tags
from lib.cuckoo.common.exceptions import CuckooOperationalError


@pytest.fixture(autouse=True)
def storage(tmp_path, request):
    storage = tmp_path / "storage"
    binaries = storage / "binaries"
    binaries.mkdir(mode=0o755, parents=True)
    analyses = storage / "analyses"
    analyses.mkdir(mode=0o755, parents=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(mode=0o755, parents=True)
    request.instance.tmp_path = tmp_path
    request.instance.storage = str(storage)
    request.instance.binary_storage = str(binaries)
    request.instance.analyses_storage = str(analyses)
    request.instance.tmpdir = str(tmpdir)


@pytest.mark.usefixtures("tmp_cuckoo_root")
class TestDatabaseEngine:
    """Test database stuff."""

    URI = None

    def setup_method(self, method):
        with NamedTemporaryFile(mode="w+", delete=False, dir=self.storage) as f:
            f.write("hehe")
        self.temp_filename = f.name
        pcap_header_base64 = b"1MOyoQIABAAAAAAAAAAAAAAABAABAAAA"
        pcap_bytes = base64.b64decode(pcap_header_base64)
        self.temp_pcap = store_temp_file(pcap_bytes, "%s.pcap" % f.name, self.tmpdir.encode())
        self.d = Database(dsn="sqlite://")
        # self.d.connect(dsn=self.URI)
        self.session = self.d.Session()
        inspector = inspect(self.d.engine)
        if inspector.get_table_names():
            stmt = delete(Machine)
            stmt2 = delete(Task)
            stmt3 = delete(machines_tags)
            stmt4 = delete(tasks_tags)
            stmt5 = delete(Tag)
            self.session.execute(stmt)
            self.session.execute(stmt2)
            self.session.execute(stmt3)
            self.session.execute(stmt4)
            self.session.execute(stmt5)
            self.session.commit()

    def teardown_method(self):
        del self.d
        shutil.rmtree(str(self.tmp_path))

    def add_url(self, url, priority=1, status="pending"):
        task_id = self.d.add_url(url, priority=priority)
        self.d.set_status(task_id, status)
        return task_id

    def test_add_tasks(self):

        # Add task.
        count = self.session.query(Task).count()
        self.d.add_path(self.temp_filename)
        assert self.session.query(Task).count() == count + 1

        # Add url.
        self.d.add_url("http://foo.bar")
        assert self.session.query(Task).count() == count + 2

    def test_error_exists(self):
        task_id = self.add_url("http://google.com/")
        self.d.add_error("A" * 1024, task_id)
        assert len(self.d.view_errors(task_id)) == 1
        self.d.add_error("A" * 1024, task_id)
        assert len(self.d.view_errors(task_id)) == 2

    def test_long_error(self):
        self.add_url("http://google.com/")
        self.d.add_error("A" * 1024, 1)
        err = self.d.view_errors(1)
        assert err and len(err[0].message) == 1024

    def test_task_set_options(self):
        assert self.d.add_path(self.temp_filename, options={"foo": "bar"}) is None
        t1 = self.d.add_path(self.temp_filename, options="foo=bar")
        assert self.d.view_task(t1).options == "foo=bar"

    def test_task_tags_str(self):
        t1 = self.d.add_path(self.temp_filename, tags="foo,,bar")
        t2 = self.d.add_path(self.temp_filename, tags="boo,,far")

        t1_tag_list = [str(x.name) for x in list(self.d.view_task(t1).tags)]
        t2_tag_list = [str(x.name) for x in list(self.d.view_task(t2).tags)]

        t1_tag_list.sort()
        t2_tag_list.sort()

        assert t1_tag_list == ["bar", "foo", "x86"]
        assert t2_tag_list == ["boo", "far", "x86"]

    def test_reschedule_file(self):
        count = self.session.query(Task).count()
        task_id = self.d.add_path(self.temp_filename)
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "file"

        # write a real sample to storage
        task_path = os.path.join(self.analyses_storage, str(task.id))
        path_mkdir(task_path)
        shutil.copy(self.temp_filename, os.path.join(task_path, "binary"))

        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "file"

    def test_reschedule_static(self):
        count = self.session.query(Task).count()
        task_ids = self.d.add_static(self.temp_filename)
        assert len(task_ids) == 1
        task_id = task_ids[0]
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "static"

        # write a real sample to storage
        static_path = os.path.join(self.binary_storage, task.sample.sha256)
        shutil.copy(self.temp_filename, static_path)

        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id[0])
        assert new_task.category == "static"

    def test_reschedule_pcap(self):
        count = self.session.query(Task).count()
        task_id = self.d.add_pcap(self.temp_pcap)
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "pcap"

        # write a real sample to storage
        pcap_path = os.path.join(self.binary_storage, task.sample.sha256)
        shutil.copy(self.temp_pcap, pcap_path)

        # reschedule the PCAP task
        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "pcap"

    def test_reschedule_url(self):
        # add a URL task
        count = self.session.query(Task).count()
        task_id = self.d.add_url("test_reschedule_url")
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "url"

        # reschedule the URL task
        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "url"

    def test_add_machine(self):
        self.d.add_machine(
            name="name1",
            label="label1",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1 tag2",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
            reserved=False,
        )
        self.d.add_machine(
            name="name2",
            label="label2",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1 tag2",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
            reserved=True,
        )
        m1 = self.d.view_machine("name1")
        m2 = self.d.view_machine("name2")

        assert m1.to_dict() == {
            "status": None,
            "locked": False,
            "name": "name1",
            "resultserver_ip": "5.6.7.8",
            "ip": "1.2.3.4",
            "tags": ["tag1tag2"],
            "label": "label1",
            "locked_changed_on": None,
            "platform": "windows",
            "snapshot": "snap0",
            "interface": "int0",
            "status_changed_on": None,
            "id": 1,
            "resultserver_port": "2043",
            "arch": "x64",
            "reserved": False,
        }

        assert m2.to_dict() == {
            "id": 2,
            "interface": "int0",
            "ip": "1.2.3.4",
            "label": "label2",
            "locked": False,
            "locked_changed_on": None,
            "name": "name2",
            "platform": "windows",
            "resultserver_ip": "5.6.7.8",
            "resultserver_port": "2043",
            "snapshot": "snap0",
            "status": None,
            "status_changed_on": None,
            "tags": ["tag1tag2"],
            "arch": "x64",
            "reserved": True,
        }

    @pytest.mark.parametrize(
        "reserved,requested_platform,requested_machine,is_serviceable",
        (
            (False, "windows", None, True),
            (False, "linux", None, False),
            (False, "windows", "label", True),
            (False, "linux", "label", False),
            (True, "windows", None, False),
            (True, "linux", None, False),
            (True, "windows", "label", True),
            (True, "linux", "label", False),
        ),
    )
    def test_serviceability(self, reserved, requested_platform, requested_machine, is_serviceable):
        self.d.add_machine(
            name="win10-x64-1",
            label="label",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
            reserved=reserved,
        )
        task = Task()
        task.platform = requested_platform
        task.machine = requested_machine
        task.tags = [Tag("tag1")]
        # tasks matching the available machines are serviceable
        assert self.d.is_serviceable(task) is is_serviceable

    @pytest.mark.parametrize(
        "task_instructions,machine_instructions,expected_results,function",
        (
            # Assign 10 tasks with the same tag to 10 available machines with that tag
            ([("tag1",10)],
             [("windows","x64","tag1",10),("windows","x86","tag2",5),("linux","x64","tag3",2)],
             {"tag1":10},
             "db_relevant_machines_to_tasks"),
            #Assign 10 tasks to 10 specific machines availables
            ([("tag1",8),("tag2",2)],
             [("windows","x64","tag1,",10),("windows","x86","tag2,",2),("linux","x64","tag3,",2)],
             {"tag1":8,"tag2":2},
             "db_relevant_machines_to_tasks"),
            #Assign tasks to their specific tags based on the number of machines for each of them
            ([("tag1",40),("tag2",2),("tag3",1)],
             [("windows","x64","tag1",80),("windows","x86","tag2",2),("linux","x64","tag3",2)],
             {"tag1":40,"tag2":2,"tag3":1},
             "db_relevant_machines_to_tasks"),
        ),
    )
    def test_db_batch_submission(self,task_instructions,machine_instructions,expected_results,function):
        errors = []
        tasks = []
        machines = []
        cleanup_tasks = []

        #Parsing machine instructions 
        for machine_instruction in machine_instructions:
            for i in range(machine_instruction[3]):
                machine_name = str(machine_instruction[0]) + str(machine_instruction[1]) + str(i)
                self.d.add_machine(name= machine_name,
                                    label= machine_name,
                                    ip="1.2.3.4",
                                    platform=machine_instruction[0],
                                    tags=machine_instruction[2],
                                    interface="int0",
                                    snapshot="snap0",
                                    resultserver_ip="5.6.7.8",
                                    resultserver_port=2043,
                                    arch=machine_instruction[1],
                                    reserved=False,
                                    )
                machines.append((machine_name,machine_instructions[2]))

        #Parsing tasks instructions
        for task_instruction in task_instructions:
            for i in range(task_instruction[1]):
                sample_name = "Sample_%s_%s"%(task_instruction[0],i)
                with open(sample_name,"w") as f:
                    f.write(sample_name)
                cleanup_tasks.append(sample_name)
                task = self.d.add_path(file_path=sample_name,tags=task_instruction[0])
                task = self.d.view_task(task)
                tasks.append(task)
        
        print("Number of tasks: %d" % len(tasks))
        #Parse the expected results
        total_task_to_be_assigned = 0
        for result in expected_results.values():
            total_task_to_be_assigned += result
        
        print("Total number of tasks that should be assigned: %d" % total_task_to_be_assigned)

        total_task_assigned = 0
        results = []
        for tag in expected_results.keys():
            results.append([tag,0])

        while len(tasks) > 0:
            watched_tasks = tasks[:5]
            relevant_function = getattr(self.d,function)
            relevant_tasks = relevant_function(watched_tasks)
            for task in watched_tasks:
                tasks.remove(task)
            for task in relevant_tasks:
                for i in range(len(results)):
                    tags = [tag.name for tag in task.tags] 
                    if results[i][0] == tags[0]:
                        results[i][1] += 1
                        break
            total_task_assigned += len(relevant_tasks)
        
        #Cleanup
        for file in cleanup_tasks:
            os.remove(file)

        #Test results
        if total_task_assigned != total_task_to_be_assigned:
            errors.append("Unexpected number of tasks assigned")
        for tag in expected_results.keys():
            for i in range(len(results)):
                if tag == results[i][0] and expected_results[tag] != results[i][1]:
                    print("%s --> %s vs %s" % (tag,expected_results[tag],results[i][1]))
                    errors.append("Unexpected number of tasks assigned for tags")
        assert not errors, "errors occured:\n{}".format("\n".join(errors))  

    @pytest.mark.parametrize(
        "task,machine,expected_result",
        (
            #Suitable task which is going to be locking this machine
           ({"label":"task1","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [0,False]
           ),
            #Suitable task which is going to be locking this machine from the label
           ({"label":"task2","machine":"machine1","platform":None,"tags":None,"package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [0,False]
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + platform)
           ({"label":"task3","machine":"machine1","platform":"windows","tags":None,"package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [1,False]
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + tags)
           ({"label":"task4","machine":"machine1","platform":None,"tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [1,False]
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + platform + tags)
           ({"label":"task5","machine":"machine1","platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [1,False]
           ),
           #Suitable task which is going to fail locking the machine as the machine is already locked
           ({"label":"task6","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":True},
           [0,False]
           ),
           #Suitable task which is going to fail locking the machine because the machine is reserved
           ({"label":"task7","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":True,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           [1,True]
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (tags) 
           ({"label":"task8","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag2","locked":False},
           [1,True]
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (platform)
           ({"label":"task9","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"linux","arch":"x64","tags":"tag1","locked":False},
           [1,True]
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (platform from package)
           ({"label":"task10","machine":None,"platform":"windows","tags":"tag1","package":"dll"},
           {"label":"machine1","reserved":False,"platform":"linux","arch":"x64","tags":"tag1","locked":False},
           [1,True]
           ),
        ),
    )
    def test_lock_machine(self,task,machine,expected_result):
        if machine["tags"] != None:
            machine_name = str(machine["label"]) + "_" + str(machine["tags"])
        else:
            machine_name = str(machine["label"])
        self.d.add_machine(name= machine_name,
                            label= machine["label"],
                            ip="1.2.3.4",
                            platform=machine["platform"],
                            tags=machine["tags"],
                            arch=machine["arch"],
                            interface="int0",
                            snapshot="snap0",
                            resultserver_ip="5.6.7.8",
                            resultserver_port=2043,
                            reserved= machine["reserved"]
                            )
        if machine["locked"]:
            try:
                queried_machine = self.session.query(Machine).filter_by(label=machine["label"])
                if queried_machine:
                    queried_machine.locked = True
                    try:
                        self.session.commit()
                        self.session.refresh(machine)
                    except SQLAlchemyError as e:
                        self.session.rollback()
                        pass
            except SQLAlchemyError as e:
                pass
        sample_name = "Sample_%s_%s"%(task["label"],task["tags"])
        with open(sample_name,"w") as f:
            f.write(sample_name)
        queried_task = self.d.add_path(file_path=sample_name,
                               machine=task["machine"],
                               platform=task["platform"],
                               tags=task["tags"],
                               )
        
        queried_task = self.d.view_task(queried_task)
        queried_task_archs, queried_task_tags = self.d._task_arch_tags_helper(queried_task)
        if task["package"] != None:
            os_version = self.d._package_vm_requires_check(task["package"])
        else:
            os_version = None
        print(self.d.get_available_machines()[0].tags)

        if expected_result[1]:
            with pytest.raises(CuckooOperationalError):
                self.d.lock_machine(label=queried_task.machine,platform=queried_task.platform,tags=queried_task_tags,arch=queried_task_archs,os_version=os_version)
        else:
            self.d.lock_machine(label=queried_task.machine,platform=queried_task.platform,tags=queried_task_tags,arch=queried_task_archs,os_version=os_version)
        #cleanup
        os.remove(sample_name)

        assert len(self.d.get_available_machines()) == expected_result[0]



