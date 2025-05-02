import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { MedecinDetailPage } from './medecin-detail.page';

const routes: Routes = [
  {
    path: '',
    component: MedecinDetailPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class MedecinDetailPageRoutingModule {}
