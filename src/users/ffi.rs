use std::collections::HashMap;
use crate::common::*;
use std::process::Command;
use crate::userdata::cloudconfig::UserConfig;
use std::ffi::{OsStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::fmt;
use libc::{c_char, uid_t, gid_t, c_int};

const GROUPADD: &str = "/usr/sbin/groupadd";
const USERMOD: &str = "/usr/sbin/usermod";
const USERADD: &str = "/usr/sbin/useradd";
const PASSWD: &str = "/usr/bin/passwd";

pub fn ensure_group(group: HashMap<String, Option<Vec<String>>>) -> Result<(), failure::Error> {

}

pub fn ensure_user(log: &Logger, user: &UserConfig) -> Result<(), failure::Error> {

}



/// Information about a particular group.
///
/// For more information, see the [module documentation](index.html).
#[derive(Clone)]
struct Group {
    gid: gid_t,
    extras: os::GroupExtras,
    pub(crate) name_arc: Arc<OsStr>,
}

impl Group {

    /// Create a new `Group` with the given group ID and name, with the
    /// rest of the fields filled in with dummy values.
    ///
    /// This method does not actually create a new group on the system — it
    /// should only be used for comparing groups in tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use users::Group;
    ///
    /// let group = Group::new(102, "database");
    /// ```
    pub fn new<S: AsRef<OsStr> + ?Sized>(gid: gid_t, name: &S) -> Self {
        let name_arc = Arc::from(name.as_ref());
        let extras = os::GroupExtras::default();

        Self { gid, name_arc, extras }
    }

    /// Returns this group’s ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use users::Group;
    ///
    /// let group = Group::new(102, "database");
    /// assert_eq!(group.gid(), 102);
    /// ```
    pub fn gid(&self) -> gid_t {
        self.gid
    }

    /// Returns this group’s name.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsStr;
    /// use users::Group;
    ///
    /// let group = Group::new(102, "database");
    /// assert_eq!(group.name(), OsStr::new("database"));
    /// ```
    pub fn name(&self) -> &OsStr {
        &*self.name_arc
    }
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("Group")
                .field("gid", &self.gid)
                .field("name_arc", &self.name_arc)
                .field("extras", &self.extras)
                .finish()
        }
        else {
            write!(f, "Group({}, {})", self.gid(), self.name().to_string_lossy())
        }
    }
}

/// Searches for a `Group` with the given group name in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
///
/// # libc functions used
///
/// - [`getgrnam_r`](https://docs.rs/libc/*/libc/fn.getgrnam_r.html)
///
/// # Examples
///
/// ```
/// use users::get_group_by_name;
///
/// match get_group_by_name("db-access") {
///     Some(group) => println!("Found group #{}", group.gid()),
///     None        => println!("Group not found"),
/// }
/// ```
pub fn get_group_by_name<S: AsRef<OsStr> + ?Sized>(groupname: &S) -> Option<Group> {
    let groupname = match CString::new(groupname.as_ref().as_bytes()) {
        Ok(u)  => u,
        Err(_) => {
            // The groupname that was passed in contained a null character,
            // which will match no usernames.
            return None;
        }
    };

    let mut group = unsafe { mem::zeroed::<c_group>() };
    let mut buf = vec![0; 2048];
    let mut result = ptr::null_mut::<c_group>();

    #[cfg(feature = "logging")]
    trace!("Running getgrnam_r for group {:?}", groupname.as_ref());

    loop {
        let r = unsafe {
            libc::getgrnam_r(groupname.as_ptr(), &mut group, buf.as_mut_ptr(), buf.len(), &mut result)
        };

        if r != libc::ERANGE {
            break;
        }

        let newsize = buf.len().checked_mul(2)?;
        buf.resize(newsize, 0);
    }

    if result.is_null() {
        // There is no such group, or an error has occurred.
        // errno gets set if there’s an error.
        return None;
    }

    if result != &mut group {
        // The result of getgrnam_r should be its input struct.
        return None;
    }

    let group = unsafe { struct_to_group(result.read()) };
    Some(group)
}