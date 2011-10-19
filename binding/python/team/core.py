import capi

class team:
    def __init__(self,team_name):
        self.th = capi.team_alloc()
        err = capi.team_init(self.th, team_name)
        if err:
            raise Exception("Team init failed.")
