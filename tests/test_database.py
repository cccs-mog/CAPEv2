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
        # This need to be done before each tests as sticky tags have been found to corrupt results
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
        "task_instructions,machine_instructions,expected_results",
        # @param task_instructions : list of tasks to be created, each tuple represent the tag to associate to tasks and the number of such tasks to create
        # @param machine_instructions : list of machines to be created, each collections represent the parameters to associate to machines and the number of such machines to create
        # @param expected_results : dictionary of expected tasks to be mapped to machines numbered by their tags 
        (
            # Assign 10 tasks with the same tag to 10 available machines with that tag
            ([("tag1",10)],
             [("windows","x64","tag1",10)],
             {"tag1":10},),
            # Assign 10 tasks (8 with one tag, 2 with another) to 8 available machines with that tag and 2 available machines with the other tag
            ([("tag1",8),("tag2",2)],
             [("windows","x64","tag1,",8),("windows","x86","tag2,",2)],
             {"tag1":8,"tag2":2}),
            # Assign 43 tasks total containing a variety of tags to 40/80 available machines with the first tag, 2/2 available machines with the second tag and 1/2 available machines with the third tag
            ([("tag1",40),("tag2",2),("tag3",1)],
             [("windows","x64","tag1",80),("windows","x86","tag2",2),("linux","x64","tag3",2)],
             {"tag1":40,"tag2":2,"tag3":1}),
        ),
    )
    def test_map_tasks_to_available_machines(self,task_instructions,machine_instructions,expected_results):
        tasks = []
        machines = []
        cleanup_tasks = []

        #Parsing machine instructions 
        for machine_instruction in machine_instructions:
            platform, archs, tags, num_of_machines = machine_instruction
            for i in range(num_of_machines):
                machine_name = str(platform) + str(archs) + str(i)
                self.d.add_machine(name= machine_name,
                                    label= machine_name,
                                    ip="1.2.3.4",
                                    platform=platform,
                                    tags=tags,
                                    interface="int0",
                                    snapshot="snap0",
                                    resultserver_ip="5.6.7.8",
                                    resultserver_port=2043,
                                    arch=archs,
                                    reserved=False,
                                    )
                machines.append((machine_name,tags))

        #Parsing tasks instructions
        for task_instruction in task_instructions:
            tags, num_of_tasks = task_instruction 
            for i in range(num_of_tasks):
                task_id = "Sample_%s_%s"%(tags,i)
                with open(task_id,"w") as f:
                    f.write(task_id)
                cleanup_tasks.append(task_id)
                task = self.d.add_path(file_path=task_id,tags=tags)
                task = self.d.view_task(task)
                tasks.append(task)
        
        #Parse the expected results
        total_task_to_be_assigned = 0
        total_task_to_be_assigned = sum(expected_results.values())
            total_task_to_be_assigned += result

        total_task_assigned = 0
        results = []
        for tag in expected_results.keys():
            results.append([tag,0])

        relevant_tasks = self.d.map_tasks_to_available_machines(tasks)
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
        assert total_task_assigned != total_task_to_be_assigned
        for tag in expected_results.keys():
            for i in range(len(results)):
                assert tag == results[i][0] and expected_results[tag] != results[i][1]

    @pytest.mark.parametrize(
        "task,machine,expected_result",
         # @param task : dictionary describing the task to be created
        # @param machine : dictionary describing the machine to be created
        # @param expected_results : list of expected locked machines after attempting the test 
        (
            #Suitable task which is going to be locking this machine
           ({"label":"task1","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (0,False)
           ),
            #Suitable task which is going to be locking this machine from the label
           ({"label":"task2","machine":"machine1","platform":None,"tags":None,"package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (0,False)
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + platform)
           ({"label":"task3","machine":"machine1","platform":"windows","tags":None,"package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (1,False)
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + tags)
           ({"label":"task4","machine":"machine1","platform":None,"tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (1,False)
           ),
            #Nonsuitable task which is going to make the function fail the locking (label + platform + tags)
           ({"label":"task5","machine":"machine1","platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (1,False)
           ),
           #Suitable task which is going to fail locking the machine as the machine is already locked
           ({"label":"task6","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag1","locked":True},
           (0,False)
           ),
           #Suitable task which is going to fail locking the machine because the machine is reserved
           ({"label":"task7","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":True,"platform":"windows","arch":"x64","tags":"tag1","locked":False},
           (1,True)
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (tags) 
           ({"label":"task8","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"windows","arch":"x64","tags":"tag2","locked":False},
           (1,True)
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (platform)
           ({"label":"task9","machine":None,"platform":"windows","tags":"tag1","package":None},
           {"label":"machine1","reserved":False,"platform":"linux","arch":"x64","tags":"tag1","locked":False},
           (1,True)
           ),
           #Suitable task which is going to not locked the machine as it is not compatible (platform from package)
           ({"label":"task10","machine":None,"platform":"windows","tags":"tag1","package":"dll"},
           {"label":"machine1","reserved":False,"platform":"linux","arch":"x64","tags":"tag1","locked":False},
           (1,True)
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
        task_id = "Sample_%s_%s"%(task["label"],task["tags"])
        with open(task_id,"w") as f:
            f.write(task_id)
        queried_task = self.d.add_path(file_path=task_id,
                               machine=task["machine"],
                               platform=task["platform"],
                               tags=task["tags"],
                               )
        
        queried_task = self.d.view_task(queried_task)
        queried_task_archs = [tag.name for tag in queried_task.tags if tag.name in ("x86", "x64")]
        queried_task_tags = [tag.name for tag in queried_task.tags if tag.name not in  queried_task_archs]
        if task["package"] != None:
            os_version = [vm_tag.strip() for vm_tag in web_conf.packages.get(task["package"]).split(",")] if web_conf.packages.get(task["package"]) else []
        else:
            os_version = None
         number_of_expected_locked_machines, should_raise_exception, should_be_locked = expected_results
        if should_raise_exception:
            with pytest.raises(CuckooOperationalError):
                returned_machine = self.d.lock_machine(label=queried_task.machine,platform=queried_task.platform,tags=queried_task_tags,arch=queried_task_archs,os_version=os_version)
                assert returned_machine == None
        else:
            returned_machine = self.d.lock_machine(label=queried_task.machine,platform=queried_task.platform,tags=queried_task_tags,arch=queried_task_archs,os_version=os_version)
            output_machine = self.d.list_machines()
            if output_machine and returned_machine is not None:
                output_machine = output_machine[0]
                #Normalizing the output in order to remove the joined tags in one of the output
                output_machine.__dict__.pop("tags",None)
                output_machine.__dict__.pop('_sa_instance_state',None)
                returned_machine.__dict__.pop('_sa_instance_state',None)
                print("%s vs %s" % (returned_machine.__dict__,output_machine.__dict__))
                assert output_machine.locked == should_be_locked 
                assert returned_machine.__dict__ == output_machine.__dict__
        #cleanup
        os.remove(task_id)
        assert len(self.d.get_available_machines()) == number_of_expected_locked_machines




